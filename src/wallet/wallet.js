/**
 * DineroeS wallet — mirrors Monero's simplewallet/wallet2 flow:
 *
 *   1. keysFromSeed(seed)              → account (a, A, b, B) + address string
 *   2. scanChain(blockchain)           → find our outputs using ONLY the view
 *                                        key (b): P' = Hs(b·R)·G + A == output key
 *   3. balancePico()                   → sum of unspent scanned outputs
 *   4. createTransaction(chain, ...)   → pick inputs + decoy ring from the live
 *                                        UTXO set, build one-time output keys
 *                                        for the recipients, sign LSAG ring
 *                                        sigs with the recovered one-time
 *                                        secrets x = Hs(b·R) + a, and return a
 *                                        fully-formed tx ready for the mempool.
 *
 * v0.1 note: amounts are visible (no RingCT), so the tx carries
 * `inputAmountTotal` — the chain uses it to bind each declared input amount to
 * its unique ring member (see blockchain.js #tryApplyTxs).
 */
import {
  keysFromSeed, randomSeed, addressFromKeys, keysFromAddress,
  scanOutput, deriveOutputSecret, parseDNE, formatDNE,
} from '../crypto/keys.js';
import { bytesToHex, hexToBytes, modN, bytesToScalarLE } from '../crypto/hash.js';
import { keyImageForOutput } from '../crypto/ring.js';
import { buildTxPrefix, prepareOutputs, assembleExtra, signTx } from '../chain/transaction.js';
import { RING_SIZE, DEFAULT_FEE } from '../constants.js';

export class Wallet {
  /**
   * @param {Uint8Array|null} seed 32-byte master secret; null ⇒ fresh random seed.
   */
  constructor(seed = null) {
    this.seed = seed ?? randomSeed();
    const k = keysFromSeed(this.seed);
    this.spendSecret = k.spendSecret;
    this.spendPublic = k.spendPublic;
    this.viewSecret = k.viewSecret;
    this.viewPublic = k.viewPublic;
    this.address = addressFromKeys(k.spendPublic, k.viewPublic);
    // Scanned state: hex(oneTimeKey) -> { amount, key, height, unlockedUntil,
    //                                     txPublicKey, isCoinbase }
    this.outputs = new Map();
    this.spentImages = new Set(); // key images we've published in outgoing txs
  }

  /** Public address string (share this to receive coins). */
  getAddress() {
    return this.address;
  }

  /**
   * Scan every block of `chain`, recovering our one-time outputs via the view
   * key only (the spend secret is never used here — exactly like a Monero
   * view-only wallet). Idempotent: safe to call again after new blocks arrive.
   * @returns {number} number of newly discovered outputs
   */
  scanChain(chain) {
    let found = 0;
    for (const block of chain.blocks) {
      const allTxs = [block.coinbase, ...block.txs];
      for (const tx of allTxs) {
        if (!tx.extra || tx.extra.length < 33) continue;
        const txPublicKeys = extractTxPublicKeys(tx.extra);
        if (txPublicKeys.length === 0) continue;
        const n = Math.min(txPublicKeys.length, tx.outputs.length);
        for (let oi = 0; oi < n; oi++) {
          const out = tx.outputs[oi];
          const candidate = scanOutput(txPublicKeys[oi], this.spendPublic, this.viewSecret);
          const keyHex = bytesToHex(candidate);
          if (keyHex !== bytesToHex(out.key)) continue; // not ours
          if (this.outputs.has(keyHex)) continue;       // already recorded
          this.outputs.set(keyHex, {
            amount: BigInt(out.amount),
            key: Uint8Array.from(out.key),
            height: block.header.height,
            unlockedUntil: tx.unlockTime ?? 0,
            txPublicKey: txPublicKeys[oi],
            isCoinbase: !!tx.isCoinbase,
          });
          found++;
        }
      }
    }
    return found;
  }

  /** Total balance in picoDNE (all discovered outputs minus locally-spent ones). */
  balancePico() {
    let total = 0n;
    for (const [keyHex, o] of this.outputs) {
      if (this.spentImages.has(this.#keyImageFor(keyHex, o))) continue;
      total += o.amount;
    }
    return total;
  }

  balance() {
    return formatDNE(this.balancePico());
  }

  /** Outputs that can be spent at `height` (maturity reached, not yet spent). */
  availableOutputs(height) {
    const avail = [];
    for (const [keyHex, o] of this.outputs) {
      if (o.unlockedUntil > 0 && height < o.unlockedUntil) continue;
      if (this.spentImages.has(this.#keyImageFor(keyHex, o))) continue;
      avail.push({ keyHex, ...o });
    }
    return avail;
  }

  /**
   * Build and sign a transaction paying `recipients` ([{address, amountPico}]).
   * Change (if any) returns to a fresh stealth output of this wallet.
   * @param {Blockchain} chain live chain (used for ring selection + heights)
   * @param {Array<{address: string|object, amountPico?: bigint, amount?: string}>} recipients
   * @param {{feePico?: bigint, randFn?: () => bigint, forceInputWithAmount?: bigint}} opts
   *   forceInputWithAmount: restrict selection to outputs with exactly this
   *   amount (v0.1 visible-amount binding works best when the spent amount is
   *   unique among live outputs; wallets can use it as a deterministic knob).
   * @returns {object} signed tx (with inputAmountTotal) ready for the mempool
   */
  createTransaction(chain, recipients, opts = {}) {
    const fee = opts.feePico ?? DEFAULT_FEE;
    const randFn = opts.randFn ?? defaultRandScalar;
    const height = chain.height + 1; // tx will land in the next block

    const outSum = recipients.reduce((a, r) => a + BigInt(r.amountPico ?? parseDNE(r.amount)), 0n);
    const needed = outSum + fee;

    // ── select inputs (greedy by largest amount, like Monero's default) ──
    let avail = this.availableOutputs(height).sort((a, b) => (a.amount < b.amount ? 1 : -1));
    if (opts.forceInputWithAmount !== undefined) {
      avail = avail.filter((o) => o.amount === BigInt(opts.forceInputWithAmount));
      if (!avail.length) throw new Error(`no available output with amount ${opts.forceInputWithAmount}`);
    }
    const selected = [];
    let inSum = 0n;
    for (const o of avail) {
      selected.push(o);
      inSum += o.amount;
      if (inSum >= needed) break;
    }
    if (inSum < needed) throw new Error(`insufficient funds: have ${inSum}, need ${needed} (incl. fee)`);

    // ── outputs: recipients + change back to ourselves ──
    const outSpecs = recipients.map((r) => ({
      amountPico: BigInt(r.amountPico ?? parseDNE(r.amount)),
      address: typeof r.address === 'string' ? keysFromAddress(r.address) : r.address,
    }));
    const change = inSum - needed;
    if (change > 0n) {
      outSpecs.push({ amountPico: change, address: { spendPublic: this.spendPublic, viewPublic: this.viewPublic } });
    }
    const preparedOuts = prepareOutputs(outSpecs, randFn);
    const extra = assembleExtra(preparedOuts);

    // ── rings: real key + RING_SIZE-1 decoys from the live UTXO set ──
    const unsignedInputs = [];
    const perInputSecrets = [];
    for (const o of selected) {
      const decoys = chain.pickRing(o.keyHex, RING_SIZE); // excludes the real key
      const ring = decoys.map(hexToBytes);
      const realIdx = Math.floor(Math.random() * (ring.length + 1));
      ring.splice(realIdx, 0, o.key); // insert the real member at a random position
      unsignedInputs.push({ ring });
      const x = deriveOutputSecret(o.txPublicKey, this.viewSecret, this.spendSecret);
      perInputSecrets.push({ realIndex: realIdx, x });
      this.spentImages.add(bytesToHex(keyImageForOutput(o.key, x)));
    }

    const unsigned = buildTxPrefix({
      inputs: unsignedInputs,
      outputs: preparedOuts.map((p) => ({ amountPico: p.amountPico, key: p.key })),
      feePico: fee,
      extra,
    });
    const signed = signTx(unsigned, perInputSecrets);
    signed.inputAmountTotal = inSum;
    return signed;
  }

  #keyImageFor(keyHex, o) {
    // Cache derived key images (scalar math once per output).
    if (!o.keyImageHex) {
      const x = deriveOutputSecret(o.txPublicKey, this.viewSecret, this.spendSecret);
      o.keyImageHex = bytesToHex(keyImageForOutput(o.key, x));
    }
    return o.keyImageHex;
  }
}

// ── helpers ─────────────────────────────────────────────────────────────────

/** Parse the [0x01 || R]* entries of a tx extra field into R byte strings. */
export function extractTxPublicKeys(extra) {
  const keys = [];
  let pos = 0;
  while (pos < extra.length) {
    const tag = extra[pos];
    if (tag === 0x01) {
      if (pos + 33 > extra.length) break;
      keys.push(extra.subarray(pos + 1, pos + 33));
      pos += 33;
    } else if (tag === 0x00) {
      pos += 33; // TAG_PAYMENT_ID || 32-byte id
    } else {
      pos += 1; // unknown/free-form tag: skip one byte (extra is free-form like Monero's)
    }
  }
  return keys;
}

function defaultRandScalar() {
  return modN(bytesToScalarLE(randomSeed()));
}
