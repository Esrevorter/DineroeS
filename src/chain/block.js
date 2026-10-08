/**
 * DineroeS blocks — mirrors Monero's `block` (cryptonote_block):
 *
 *   header = { majorVersion, minorVersion, timestamp, prevId, nonce,
 *              difficulty, cumulativeDifficulty, blockHeight }  (+ Merkle root)
 *   minerTx = the coinbase transaction (special: no inputs, one output paying
 *             base reward + fees to a stealth key derived from the MINER's
 *             address; Monero puts that address in extra as TAG_MINER).
 *
 * Block id (what peers reference as "the hash") = keccak256(header blob),
 * exactly like Monero's get_block_hashing_blob → block_id. PoW is checked
 * against `difficulty` with cnSlowHash (see docs/architecture.md).
 */
import { cnFastHash, cnSlowHash, concatBytes, meetsDifficulty, bytesToHex } from '../crypto/hash.js';
import { wU8, wU64, wVarint, wBytes, ByteReader } from './serialize.js';
import { merkleRootFromBlobs } from './merkle.js';
import { serializeTx } from './transaction.js';
import { blockReward } from './emission.js';
import { createOutputKeys } from '../crypto/keys.js';
import {
  GENESIS_TIMESTAMP, GENESIS_DIFFICULTY, GENESIS_COINBASE_TX_EXTRA_MESSAGE,
  GENESIS_NONCE, COIN_NAME, COINBASE_MATURITY,
} from '../constants.js';

export const BLOCK_MAJOR_VERSION = 1;
export const BLOCK_MINOR_VERSION = 0;

// ── coinbase (miner) tx ─────────────────────────────────────────────────────
/**
 * Build the coinbase transaction for height h paying `rewardPico` to the
 * miner's stealth output. Like Monero, the coinbase uses version-1-style
 * output keys but has NO inputs and NO ring signature (nothing to authorize —
 * it's created by consensus rule "block N pays at most reward(N)").
 * @param {number} h block height
 * @param {bigint} rewardPico base+fees in picoDNE
 * @param {{spendPublic: Uint8Array}} minerAccount - miner's public spend key A
 * @param {Uint8Array(32)} viewPublic miner's public view key B
 * @param {bigint} r ephemeral scalar for the stealth address
 */
export function buildCoinbaseTx(h, rewardPico, minerAccount, viewPublic, r) {
  const { txPublicKey, oneTimeSpendKey } = createOutputKeys(minerAccount.spendPublic, viewPublic, r);
  return {
    version: 1,
    unlockTime: h + COINBASE_MATURITY, // Monero sets unlock_time = height+60 for coinbase
    inputs: [],
    outputs: [{ amount: rewardPico, key: oneTimeSpendKey }],
    // TAG_TX_PUBKEY || R — same convention as regular txs (assembleExtra), so
    // the miner can scan and recover the output secret with their view key.
    extra: concatBytes(Uint8Array.from([0x01]), txPublicKey),
    feePico: 0n,
    signatures: [],
    isCoinbase: true,
  };
}

// ── header serialization ────────────────────────────────────────────────────
export function serializeHeader(hdr) {
  return concatBytes(
    wU8(hdr.majorVersion),
    wU8(hdr.minorVersion),
    wU64(hdr.timestamp),
    wBytes(hdr.prevId),
    wU64(hdr.height),
    wBytes(hdr.merkleRoot),
    wU64(hdr.difficulty),
    wU64(hdr.cumulativeDifficulty),
    wU64(hdr.nonce),
  );
}

export function deserializeHeader(bytes) {
  const r = new ByteReader(bytes);
  return {
    majorVersion: r.u8(),
    minorVersion: r.u8(),
    timestamp: Number(r.u64()),
    prevId: Uint8Array.from(r.bytes()),
    height: Number(r.u64()),
    merkleRoot: Uint8Array.from(r.bytes()),
    difficulty: r.u64(),
    cumulativeDifficulty: r.u64(),
    nonce: Number(r.u64()),
  };
}

/** The exact byte string that gets PoW-hashed (Monero: hashing_blob). */
export function blockHashingBlob(hdr) {
  return serializeHeader(hdr);
}

export function computeBlockId(hdr) {
  return cnFastHash(blockHashingBlob(hdr));
}

/** PoW check: cn_slow_hash_lite(blob) must meet hdr.difficulty. */
export function checkProofOfWork(hdr) {
  const powHash = cnSlowHash(blockHashingBlob(hdr));
  return meetsDifficulty(powHash, BigInt(hdr.difficulty));
}

// ── full block assembly / validation ────────────────────────────────────────

/**
 * Assemble a block from header fields + txs. Recomputes the Merkle root over
 * [coinbase, ...txs] so callers can't inject a wrong root.
 */
export function assembleBlock({ timestamp, prevId, height, difficulty, cumulativeDifficulty, nonce, minerAddress, rSeed, txs = [], feesPico = 0n }) {
  const reward = blockReward(height, feesPico);
  const coinbase = buildCoinbaseTx(height, reward, minerAddress.account, minerAddress.viewPublic, rSeed);
  const allTxs = [coinbase, ...txs];
  const blobs = allTxs.map((t) => (t.isCoinbase ? serializeCoinbase(t) : serializeTx(t)));
  const merkleRoot = merkleRootFromBlobs(blobs);
  const hdr = {
    majorVersion: BLOCK_MAJOR_VERSION,
    minorVersion: BLOCK_MINOR_VERSION,
    timestamp,
    prevId,
    height,
    merkleRoot,
    difficulty,
    cumulativeDifficulty,
    nonce,
  };
  return { header: hdr, coinbase, txs, id: bytesToHex(computeBlockId(hdr)) };
}

export function serializeCoinbase(cb) {
  // coinbase shares tx format minus signatures: prefix || fee || sigcount(0)
  return concatBytes(serializeCoinbasePrefix(cb), wU64(0n), wVarint(0));
}

function serializeCoinbasePrefix(cb) {
  const parts = [wU8(cb.version), wU64(cb.unlockTime)];
  parts.push(wVarint(0)); // zero inputs
  parts.push(wVarint(cb.outputs.length));
  for (const out of cb.outputs) {
    parts.push(wU64(out.amount));
    parts.push(wBytes(out.key));
  }
  parts.push(wBytes(cb.extra));
  return concatBytes(...parts);
}

/**
 * Validate everything about a block except chain-context rules (which the
 * Blockchain class does): Merkle root consistency, coinbase reward cap, PoW.
 * @param {{skipPowCheck?: boolean}} opts test hook — never used by daemons
 */
export function verifyBlockStructure(block, opts = {}) {
  const { header, coinbase, txs } = block;
  const blobs = [serializeCoinbase(coinbase), ...txs.map(serializeTx)];
  const expected = merkleRootFromBlobs(blobs);
  if (!Buffer.from(expected).equals(Buffer.from(header.merkleRoot))) {
    return { ok: false, reason: 'merkle root mismatch' };
  }
  const totalFees = txs.reduce((a, t) => a + t.feePico, 0n);
  const maxReward = blockReward(header.height, totalFees);
  const cbAmount = coinbase.outputs.reduce((a, o) => a + o.amount, 0n);
  if (cbAmount > maxReward) return { ok: false, reason: 'coinbase pays too much' };
  if (!coinbase.isCoinbase || coinbase.inputs.length !== 0) {
    return { ok: false, reason: 'bad coinbase structure' };
  }
  if (!opts.skipPowCheck && !checkProofOfWork(header)) return { ok: false, reason: 'invalid proof of work' };
  return { ok: true };
}

/**
 * Proof-of-work miner: grind nonces until cn_slow_hash_lite(blob) meets the
 * difficulty. Returns the solved header (mutated copy) or null after maxTries.
 * Difficulty 1 passes almost instantly — good for demos/tests.
 */
export function mineBlock(block, maxTries = 500_000) {
  const hdr = { ...block.header };
  const startNonce = hdr.nonce || 0;
  for (let i = 0; i < maxTries; i++) {
    hdr.nonce = startNonce + i;
    if (checkProofOfWork(hdr)) {
      const solvedHeader = hdr;
      const id = bytesToHex(computeBlockId(solvedHeader));
      return { ...block, header: solvedHeader, id };
    }
  }
  return null;
}

// ── genesis ─────────────────────────────────────────────────────────────────
/**
 * Deterministic DineroeS genesis block. Like Monero, genesis is hardcoded,
 * pays nothing, carries an extra message, and its id anchors the chain.
 */
export function genesisBlock() {
  const prevId = new Uint8Array(32); // zeros
  const messageBytes = new TextEncoder().encode(GENESIS_COINBASE_TX_EXTRA_MESSAGE);
  const coinbase = {
    version: 1,
    unlockTime: COINBASE_MATURITY,
    inputs: [],
    outputs: [], // pays nothing (GENESIS_REWARD === 0)
    extra: concatBytes(Uint8Array.from([0x02 /* TAG_EXTRA_MESSAGE-like */]), messageBytes),
    feePico: 0n,
    signatures: [],
    isCoinbase: true,
  };
  const merkleRoot = merkleRootFromBlobs([serializeCoinbase(coinbase)]);
  const hdr = {
    majorVersion: BLOCK_MAJOR_VERSION,
    minorVersion: BLOCK_MINOR_VERSION,
    timestamp: GENESIS_TIMESTAMP,
    prevId,
    height: 0,
    merkleRoot,
    difficulty: GENESIS_DIFFICULTY,
    cumulativeDifficulty: GENESIS_DIFFICULTY,
    nonce: GENESIS_NONCE,
  };
  return { header: hdr, coinbase, txs: [], id: bytesToHex(computeBlockId(hdr)), genesis: true };
}

export const GENESIS_COIN_NAME = COIN_NAME;
