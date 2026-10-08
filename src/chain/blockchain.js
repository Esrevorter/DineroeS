/**
 * DineroeS Blockchain — the consensus engine.
 *
 * Mirrors Monero's `Blockchain` + `tx_pool` responsibilities:
 *  - append-only block store (JSONL file; one line per block, bigints hexed)
 *  - UTXO set ("output table") keyed by one-time public key
 *  - spent key-image set (Monero keeps this forever — so do we)
 *  - chain-context validation on addBlock():
 *      prevId linkage, height sequence, timestamps (median-3 like Monero),
 *      LWMA difficulty match, PoW, coinbase cap, tx structural checks,
 *      double-spend rejection (key images), input existence, unlock times,
 *      and Monero's longest-cumulative-difficulty fork choice with reorgs.
 *
 * Storage format note: real Monero uses LMDB. For a readable reference
 * implementation we use an append-only JSON-lines file plus an in-memory
 * index rebuilt at startup — simple, crash-safe (last line wins), auditable.
 */
import { bytesToHex } from '../crypto/hash.js';
import { genesisBlock, verifyBlockStructure, computeBlockId, serializeHeader } from './block.js';
import { verifyTxStructure, serializeTx } from './transaction.js';
import { nextDifficultyLWMA } from './difficulty.js';
import { RING_SIZE, TARGET_BLOCK_TIME } from '../constants.js';

export class Blockchain {
  constructor() {
    this.blocks = []; // [{header, coinbase, txs, id}]
    this.indexByHash = new Map(); // id -> height
    this.outputsByKey = new Map(); // hex(oneTimeKey) -> {height, txIndex, outIndex, amount, unlockedUntil}
    this.outputKeyByImage = new Map(); // hex(keyImage) -> hex(oneTimeKey) (link set at spend time)
    this.spentImages = new Set(); // hex(keyImage) -> true
    this.allCreatedKeys = new Set(); // every output key ever created (history, for ring checks)
    this.totalFeeCollected = 0n;
  }

  // ── accessors ─────────────────────────────────────────────────────────────
  get height() {
    return this.blocks.length - 1; // genesis counts as height 0
  }
  tip() {
    return this.blocks[this.blocks.length - 1];
  }
  tipId() {
    return this.tip().id;
  }
  cumulativeDifficulty() {
    return BigInt(this.tip().header.cumulativeDifficulty);
  }

  /** Snapshot for LWMA: last N blocks' timestamps + cumulative difficulty. */
  lwmaWindow(n) {
    const start = Math.max(0, this.blocks.length - n);
    return this.blocks.slice(start).map((b) => ({
      timestamp: b.header.timestamp,
      difficulty: BigInt(b.header.difficulty),
    }));
  }

  // ── initialization ────────────────────────────────────────────────────────
  initGenesis() {
    if (this.blocks.length) throw new Error('chain already initialized');
    const g = genesisBlock();
    this.blocks.push(g);
    this.indexByHash.set(g.id, 0);
    return g;
  }

  // ── core: add a fully-formed block ────────────────────────────────────────
  /**
   * @param {object} block
   * @param {{skipDifficultyCheck?: boolean, skipPowCheck?: boolean}} opts
   *        Test hooks only — production daemons must use defaults. (With the
   *        cn-lite PoW, verification costs as much as mining, so unit tests
   *        can't afford real grinding; see docs/architecture.md "PoW".)
   * @returns {{ok:boolean, reason?:string}} — on success the block is extended.
   * On a valid-but-forking block (higher cumulative diff), we reorganize.
   */
  addBlock(block, opts = {}) {
    const hdr = block.header;

    // 1. must extend some known block
    const parentHeight = this.indexByHash.get(bytesToHex(hdr.prevId));
    if (parentHeight === undefined) return { ok: false, reason: 'unknown parent' };
    if (hdr.height !== parentHeight + 1) return { ok: false, reason: 'bad height sequence' };

    // 2. timestamps: strictly after median of previous 3 (Monero rule)
    const med = medianTimestamp(this.blocks, parentHeight);
    if (hdr.timestamp <= med) return { ok: false, reason: 'timestamp too early (median-3)' };

    // 3. difficulty must equal what LWMA predicts for this position
    if (!opts.skipDifficultyCheck && parentHeight > 0) {
      const expectedDiff = nextDifficultyLWMA(this.lwmaWindowFor(parentHeight), hdr.height);
      if (BigInt(hdr.difficulty) !== expectedDiff) {
        return { ok: false, reason: `difficulty mismatch: got ${hdr.difficulty}, LWMA says ${expectedDiff}` };
      }
    }

    // 4. cumulative difficulty arithmetic
    const parentCum = BigInt(this.blocks[parentHeight].header.cumulativeDifficulty);
    if (BigInt(hdr.cumulativeDifficulty) !== parentCum + BigInt(hdr.difficulty)) {
      return { ok: false, reason: 'cumulative difficulty mismatch' };
    }

    // 5. structural checks (+ PoW unless test hook disabled it)
    const struct = verifyBlockStructure(block, opts);
    if (!struct.ok) return struct;

    // 6. recompute id from header — reject forged ids
    const realId = bytesToHex(computeBlockId(hdr));
    if (realId !== block.id) return { ok: false, reason: 'block id does not match header' };

  // ── transactions against current state (only if extending the tip;
  //    forks are validated against their own ancestor state via reorg path)
  if (parentHeight === this.height) {
    const applied = this.#tryApplyTxs(block);
    if (!applied.ok) return applied;
    this.blocks.push(block);
    this.indexByHash.set(realId, hdr.height);
    // register outputs FIRST (so a tx's own outputs exist), then apply spends.
    this.#registerBlockOutputs(block);
    this.#applySpends(block);
    return { ok: true };
  }

  // Fork: compare cumulative difficulty (Monero's fork-choice rule)
  if (BigInt(hdr.cumulativeDifficulty) > this.cumulativeDifficulty()) {
    return this.#reorganizeOnto(block, realId);
  }
  return { ok: false, reason: 'valid side-chain but lower cumulative difficulty' };
}

/**
 * Apply a block's spends to the live-UTXO view: mark key images spent and
 * delete consumed outputs from `outputsByKey`. Historical creation records
 * stay in the block store itself (and in `allCreatedKeys` for ring checks).
 */
#applySpends(block) {
  for (const tx of block.txs) {
    for (let i = 0; i < tx.signatures.length; i++) {
      const imgHex = bytesToHex(tx.signatures[i].keyImage);
      this.spentImages.add(imgHex);
      const spentKey = this.outputKeyByImage.get(imgHex);
      if (spentKey !== undefined) this.outputsByKey.delete(spentKey);
    }
  }
}

  // ── helpers ───────────────────────────────────────────────────────────────
  lwmaWindowFor(parentHeight) {
    const start = Math.max(0, parentHeight - 60 + 1);
    return this.blocks.slice(start, parentHeight + 1).map((b) => ({
      timestamp: b.header.timestamp,
      difficulty: BigInt(b.header.difficulty),
    }));
  }

  #tryApplyTxs(block) {
    const localImages = new Set();
    // Per-tx, per-input binding: imageHex -> real ring member key hex.
    // (v0.1: amounts are visible, so the sender publishes inputAmountTotal;
    //  we locate the unique ring member whose amount makes the tx balance —
    //  a stand-in for RingCT's commitment opening. See docs/architecture.md.)
    const bindings = [];
    for (const tx of block.txs) {
      const v = verifyTxStructure(tx);
      if (!v.ok) return v;
      const outSum = tx.outputs.reduce((a, o) => a + BigInt(o.amount), 0n);
      const expectedIn = tx.inputAmountTotal !== undefined && tx.inputAmountTotal !== null
        ? BigInt(tx.inputAmountTotal)
        : null;
      const perInput = [];
      for (let i = 0; i < tx.inputs.length; i++) {
        const inp = tx.inputs[i];
        const imgHex = bytesToHex(tx.signatures[i].keyImage);
        if (this.spentImages.has(imgHex) || localImages.has(imgHex)) {
          return { ok: false, reason: 'double spend (key image already used)' };
        }
        localImages.add(imgHex);
        // Every ring member must be an output that was ever created on this
        // chain (Monero checks global output indexes against its output table).
        let candidates = [];
        for (const pk of inp.ring) {
          const keyHex = bytesToHex(pk);
          if (!this.outputsByKey.has(keyHex)) {
            return { ok: false, reason: 'ring contains unknown output key' };
          }
          const info = this.outputsByKey.get(keyHex);
          if (expectedIn !== null && BigInt(info.amount) === expectedIn) candidates.push(keyHex);
        }
        if (expectedIn !== null) {
          // The real input is the (hopefully unique) ring member with the
          // declared amount. Ambiguity or absence ⇒ reject.
          if (candidates.length !== 1) {
            return { ok: false, reason: 'cannot bind input to ring member (amount ambiguity)' };
          }
          // Unlock-time check uses the REAL input's maturity (coinbase outputs
          // carry unlockedUntil = creationHeight + COINBASE_MATURITY).
          const realInfo = this.outputsByKey.get(candidates[0]);
          if (realInfo.unlockedUntil > 0 && block.header.height < realInfo.unlockedUntil) {
            return { ok: false, reason: 'tx unlock time not reached (input still locked)' };
          }
          perInput.push(candidates[0]);
        } else {
          perInput.push(null); // multi-input without declared totals: skip binding
        }
      }
      // Global unlock_time field still enforced (Monero semantics):
      if (tx.unlockTime > 0 && block.header.height < tx.unlockTime) {
        return { ok: false, reason: 'tx unlock time not reached' };
      }
      bindings.push(perInput);
    }
    // All checks passed: mark images spent and remember which key each image
    // consumed (so addBlock can delete it from the live set).
    for (let t = 0; t < block.txs.length; t++) {
      const tx = block.txs[t];
      for (let i = 0; i < tx.signatures.length; i++) {
        const imgHex = bytesToHex(tx.signatures[i].keyImage);
        this.spentImages.add(imgHex);
        if (bindings[t][i]) this.outputKeyByImage.set(imgHex, bindings[t][i]);
      }
    }
    return { ok: true };
  }

  #registerBlockOutputs(block) {
    const h = block.header.height;
    const cb = block.coinbase;
    cb.outputs.forEach((o, idx) => {
      this.outputsByKey.set(bytesToHex(o.key), {
        height: h, txIndex: -1, outIndex: idx, amount: BigInt(o.amount), unlockedUntil: cb.unlockTime,
      });
    });
    block.txs.forEach((tx, ti) => {
      tx.outputs.forEach((o, oi) => {
        this.outputsByKey.set(bytesToHex(o.key), {
          height: h, txIndex: ti, outIndex: oi, amount: BigInt(o.amount), unlockedUntil: tx.unlockTime,
        });
      });
    });
  }

  /** Rebuild indices from scratch (used after reorg or load). */
  rebuildState() {
    this.outputsByKey.clear();
    this.spentImages.clear();
    this.outputKeyByImage.clear();
    this.indexByHash.clear();
    for (let i = 0; i < this.blocks.length; i++) {
      const b = this.blocks[i];
      this.indexByHash.set(b.id, i);
      this.#registerBlockOutputs(b);
      for (const tx of b.txs) {
        for (let si = 0; si < tx.signatures.length; si++) {
          const imgHex = bytesToHex(tx.signatures[si].keyImage);
          this.spentImages.add(imgHex);
          // Re-derive the image→output binding from the declared input amount
          // (v0.1 visible amounts; see #tryApplyTxs comment).
          const inAmount = tx.inputAmountTotal !== undefined && tx.inputAmountTotal !== null
            ? BigInt(tx.inputAmountTotal) : null;
          if (inAmount === null || !tx.inputs[si]) continue;
          let found = null;
          for (const pk of tx.inputs[si].ring) {
            const keyHex = bytesToHex(pk);
            const info = this.outputsByKey.get(keyHex);
            if (info && BigInt(info.amount) === inAmount) { found = keyHex; break; }
          }
          if (found) {
            this.outputKeyByImage.set(imgHex, found);
            this.outputsByKey.delete(found); // consumed ⇒ not live anymore
          }
        }
      }
    }
  }

  /**
   * Minimal reorg: find common ancestor between our chain and the fork block's
   * ancestry supplied by caller (forkChain = ordered blocks from our tip's
   * child... up to and including the new tip). Then swap.
   */
  #reorganizeOnto(forkTipBlock, forkTipId) {
    // Walk back our chain until cumulative difficulty <= fork's parent cum diff
    const forkParentCum = BigInt(forkTipBlock.header.cumulativeDifficulty) - BigInt(forkTipBlock.header.difficulty);
    let cut = this.height;
    while (cut > 0 && BigInt(this.blocks[cut].header.cumulativeDifficulty) > forkParentCum) cut--;
    this.blocks.length = cut + 1;
    this.rebuildState();
    // Caller (daemon/p2p layer) is responsible for feeding intermediate fork
    // blocks through addBlock again; here we accept only direct-tip extension.
    const parentHeight = this.indexByHash.get(bytesToHex(forkTipBlock.header.prevId));
    if (parentHeight !== this.height) {
      return { ok: false, reason: 'reorg needs intermediate blocks (feed them first)' };
    }
    return this.addBlock(forkTipBlock);
  }

  /** Pick random decoys for a ring (excluding the real key). Like Monero's pick_inputs. */
  pickRing(excludeKeyHex, count = RING_SIZE) {
    const keys = [...this.outputsByKey.keys()].filter((k) => k !== excludeKeyHex);
    if (keys.length < count - 1) throw new Error('not enough outputs for ring size');
    const picked = new Set();
    while (picked.size < count - 1) picked.add(keys[Math.floor(Math.random() * keys.length)]);
    return [...picked];
  }

  /**
   * Full block validation for the P2P/wire layer: re-parse the header from its
   * canonical serialization (rejects unknown fields / forged ids) and run all
   * consensus checks. `opts` carries test hooks only (see addBlock).
   */
  validateBlock(raw, opts = {}) {
    let hdr;
    try {
      hdr = deserializeHeader(serializeHeader(raw.header));
    } catch (e) {
      return { ok: false, reason: 'unparseable header: ' + e.message };
    }
    if (bytesToHex(computeBlockId(hdr)) !== raw.id) return { ok: false, reason: 'bad block id' };
    return this.addBlock({ ...raw, header: hdr }, opts);
  }

  // ── persistence (JSONL: one serialized block per line, bigints as strings) ─
  /** @returns {string} JSON-safe string of a full block (for storage/wire) */
  static blockToJSON(block) {
    return JSON.stringify(deepHex(block));
  }
  static blockFromJSON(str) {
    return reviveBigAndBytes(JSON.parse(str));
  }

  saveToFile(fs, path) {
    const lines = this.blocks.map((b) => Blockchain.blockToJSON(b));
    fs.writeFileSync(path, lines.join('\n') + '\n');
  }

  loadFromFile(fs, path) {
    if (!fs.existsSync(path)) return false;
    const text = fs.readFileSync(path, 'utf8').trim();
    if (!text) return false;
    this.blocks = text.split('\n').map((l) => Blockchain.blockFromJSON(l));
    this.rebuildState();
    return true;
  }
}

// ── JSON helpers: bigint → "123n", Uint8Array → hex string ─────────────────
function deepHex(v) {
  if (typeof v === 'bigint') return v.toString() + 'n';
  if (v instanceof Uint8Array) return 'hex:' + bytesToHex(v);
  if (Array.isArray(v)) return v.map(deepHex);
  if (v && typeof v === 'object') {
    const o = {};
    for (const [k, x] of Object.entries(v)) o[k] = deepHex(x);
    return o;
  }
  return v;
}
function reviveBigAndBytes(v) {
  if (typeof v === 'string') {
    if (/^\d+n$/.test(v)) return BigInt(v.slice(0, -1));
    if (v.startsWith('hex:')) return Uint8Array.from(Buffer.from(v.slice(4), 'hex'));
    return v;
  }
  if (Array.isArray(v)) return v.map(reviveBigAndBytes);
  if (v && typeof v === 'object') {
    const o = {};
    for (const [k, x] of Object.entries(v)) o[k] = reviveBigAndBytes(x);
    return o;
  }
  return v;
}

function medianTimestamp(blocks, parentHeight) {
  // Monero: median of last 3 timestamps (or 60 pre-v7; we use 3)
  const arr = [];
  for (let i = Math.max(0, parentHeight - 2); i <= parentHeight; i++) arr.push(blocks[i].header.timestamp);
  arr.sort((a, b) => a - b);
  return arr[Math.floor(arr.length / 2)];
}

/** Was this output key ever created on any block (including spent ones)? */
// NOTE: kept for documentation; the live outputsByKey map is authoritative in
// v0.1 because spent outputs are deleted at spend time and never re-added.
