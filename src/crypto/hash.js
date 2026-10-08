/**
 * DineroeS hashing layer.
 *
 * Monero uses Keccak-256 (the original Keccak, NOT NIST SHA3-256) for nearly
 * everything: block hashes, tx hashes, hash_to_scalar, key images. We use
 * @noble/hashes' `keccak_256` which is the same primitive as Monero's
 * `crypto::cn_fast_hash`.
 *
 * Also provides:
 *  - cn_slow_hash_lite: a simplified CryptoNight-style memory-hard PoW.
 *    Real CryptoNight requires AES-NI scrypt-like mixing in C; here we build
 *    an honest JS analogue with a documented security trade-off (see docs/).
 *  - hash_to_scalar / hash_to_point equivalents of Monero's H_s and H_p.
 */
import { keccak_256 } from '@noble/hashes/sha3.js';
import { sha512 } from '@noble/hashes/sha2.js';
import * as ed from '@noble/ed25519';
import { ED25519_SCALAR_ORDER, HASH_TO_SCALAR_PREFIX, HASH_TO_POINT_PREFIX } from '../constants.js';

ed.hashes.sha512 = sha512; // enable noble sync API

const G = ed.Point.BASE;
const CURVE = ed.Point.CURVE();

// ── byte helpers ────────────────────────────────────────────────────────────
export function bytesToHex(b) {
  return Buffer.from(b).toString('hex');
}
export function hexToBytes(h) {
  return Uint8Array.from(Buffer.from(h, 'hex'));
}
export function concatBytes(...arrs) {
  const total = arrs.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/** Canonical little-endian 32-byte scalar encoding, like Monero's epee. */
export function scalarToBytes(s) {
  const out = new Uint8Array(32);
  let n = modN(s);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

export function bytesToScalarLE(bytes) {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}

/** 8-byte little-endian unsigned integer (block heights, timestamps). */
export function u64LE(n) {
  const out = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

// ── core hashes ─────────────────────────────────────────────────────────────
/** cn_fast_hash — Keccak-256. The workhorse hash of the protocol. */
export function cnFastHash(data) {
  return keccak_256(toUint8(data));
}

/** Hash of arbitrary data to a reduced scalar mod ℓ (Monero's H_s). */
export function hashToScalar(data) {
  const prefixed = concatBytes(Uint8Array.from([HASH_TO_SCALAR_PREFIX]), toUint8(data));
  const digest = cnFastHash(prefixed);
  // Interpret as LE 256-bit, reduce mod ℓ (same as ge_frombytes + scalar_reduce in Monero)
  return modN(bytesToScalarLE(digest));
}

/**
 * Hash-to-curve point on the Ed25519 main subgroup (Monero's H_p(P)).
 *
 * Monero's old Hp was try-and-increment over curve points; modern Monero uses
 * a similar double-and-add approach. We do deterministic try-and-increment:
 *   for i in 0.. : bytes = keccak256(prefix || data || u64(i)) treated as a
 *   compressed Ed25519 point; attempt decompression; multiply by cofactor 8
 *   and reject identity. ~50% of 32-byte strings decompress to valid points,
 *   so expected iterations ≈ 2. Result is guaranteed in the prime-order
 *   subgroup (cofactor cleared), like geP3 from Monero's crypto ops.
 */
export function hashToPoint(data) {
  const base = concatBytes(Uint8Array.from([HASH_TO_POINT_PREFIX]), toUint8(data));
  for (let counter = 0; counter < 1000; counter++) {
    const seed = concatBytes(base, u64LE(counter));
    const digest = cnFastHash(seed);
    let point;
    try {
      point = ed.Point.fromBytes(digest, false);
    } catch {
      continue;
    }
    const cleared = point.clearCofactor();
    if (cleared.is0()) continue;
    return cleared;
  }
  throw new Error('hashToPoint: no valid point found');
}

/** Key image: I = x · H_p(P), exactly as in Monero whitepaper §"Key Image". */
export function deriveKeyImage(secretScalar, publicKeyPoint) {
  const hp = hashToPoint(publicKeyPoint.toBytes());
  return hp.multiply(secretScalar).toBytes();
}

// ── modular arithmetic (scalars mod ℓ) ─────────────────────────────────────
export function modN(a) {
  return ((a % ED25519_SCALAR_ORDER) + ED25519_SCALAR_ORDER) % ED25519_SCALAR_ORDER;
}
export function addModN(a, b) {
  return modN(a + b);
}
export function subModN(a, b) {
  return modN(a - b);
}
export function mulModN(a, b) {
  return modN(a * b);
}
export function invModN(a) {
  // Extended Euclid via noble's invert
  return ed.etc.invert(a, ED25519_SCALAR_ORDER);
}

/** Scalar multiplication of the base point: P = s·G. */
export function scalarmultBase(s) {
  return G.multiply(modN(s));
}

/** Multi-scalar helper: a·A + b·B. */
export function scalarmultPoint(point, s) {
  return point.multiply(modN(s));
}

// ── CryptoNight-lite PoW ────────────────────────────────────────────────────
/**
 * A memory-hard-ish hash for DineroeS blocks. This is NOT real CryptoNight
 * (which needs AES rounds over a 2MB scratchpad). It is a Keccak-based
 * sponge with a large sequential mixing loop that is cheap to verify once
 * (verifier recomputes it too, so verification cost equals mining cost —
 * acceptable for a JS reference chain; see docs/architecture.md "PoW").
 *
 * Scratchpad: 2^18 bytes (~256 KB) — keeps solo CPU miners practical in JS.
 */
const CNL_SCRATCH_BYTES = 1 << 18;
const CNL_ITERATIONS = 64;

export function cnSlowHash(input) {
  const data = toUint8(input);
  // Phase 1: seed a scratchpad from keccak of the input, iterated.
  let h = cnFastHash(data);
  const pad = new Uint8Array(CNL_SCRATCH_BYTES);
  for (let i = 0; i < CNL_ITERATIONS; i++) {
    h = cnFastHash(concatBytes(h, u64LE(i)));
    pad.set(h, (i * 32) % (CNL_SCRATCH_BYTES - 32));
  }
  // Phase 2: pseudo-random reads/writes over the pad (memory-hardness flavor).
  let idx = bytesToScalarLE(h) % BigInt(CNL_SCRATCH_BYTES / 32);
  for (let i = 0; i < CNL_ITERATIONS * 8; i++) {
    const cell = idx * 32n;
    const chunk = pad.subarray(Number(cell), Number(cell) + 32);
    h = cnFastHash(concatBytes(h, chunk));
    pad.set(h, Number(cell));
    idx = bytesToScalarLE(h) % BigInt(CNL_SCRATCH_BYTES / 32);
  }
  // Final squeeze.
  return cnFastHash(concatBytes(h, pad));
}

/** Check whether a hash meets difficulty target (Monero: diff*hash <= 2^256). */
export function meetsDifficulty(hashBytes, difficultyBig) {
  const hashNum = bytesToScalarLE(reverseInPlace(Uint8Array.from(hashBytes))); // treat BE for target compare
  // 2^256 / difficulty >= hash  ⇔  hash * difficulty < 2^256
  return hashNum * difficultyBig < 2n ** 256n;
}

function reverseInPlace(a) {
  a.reverse();
  return a;
}

function toUint8(x) {
  if (x instanceof Uint8Array) return x;
  if (Array.isArray(x)) return Uint8Array.from(x);
  if (typeof x === 'string') return Uint8Array.from(Buffer.from(x, 'utf8'));
  if (Buffer.isBuffer(x)) return new Uint8Array(x);
  throw new TypeError('cannot convert to Uint8Array: ' + typeof x);
}
