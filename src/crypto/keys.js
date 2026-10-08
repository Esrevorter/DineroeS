/**
 * DineroeS key management — mirrors Monero's two-key wallet model exactly:
 *
 *   Monero                          DineroeS
 *   ------------------------------  ---------------------------------
 *   spend secret key  a   (scalar)  spendSecret  (32-byte seed / scalar)
 *   spend public key  A = a·G       spendPublic
 *   view secret key   b = Hs(a)     viewSecret = hashToScalar(spendSecretBytes)
 *   view public key   B = b·G       viewPublic
 *   address           (A, B) encoded with base58 + checksum
 *
 * Stealth (one-time) addresses follow the Monero whitepaper §"One-Time Keys":
 *   sender picks random r;
 *   shared secret  ss = r·B  (sender computes from recipient's view pub)
 *   one-time spend key  P = Hs(ss)·G + A
 *   one-time view key   Q = r·A            (recipient recovers via b·P' etc.)
 * Recipient scans blocks computing  Hs(b·(r·A))·G + A == P  for every tx pubkey.
 */
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { cnFastHash, hashToScalar, concatBytes, bytesToHex, hexToBytes, modN, addModN, mulModN, scalarmultBase, scalarmultPoint, scalarToBytes, bytesToScalarLE } from './hash.js';
import { encode as b58encode, decode as b58decode } from './base58.js';
import { ADDRESS_PREFIX_STANDARD, COIN } from '../constants.js';

ed.hashes.sha512 = sha512;

const G = ed.Point.BASE;

// ── Account keys ────────────────────────────────────────────────────────────

/**
 * Derive the full key pair set from a 32-byte seed (the wallet's master secret).
 * Identical construction to Monero: spend = seed-derived scalar; view = Hs(spend).
 */
export function keysFromSeed(seedBytes) {
  if (seedBytes.length !== 32) throw new Error('seed must be 32 bytes');
  const spendSecret = modN(bytesToScalarLE(cnFastHash(concatBytes(Uint8Array.from([0x73 /* 's' */]), seedBytes))));
  const spendPublicPoint = scalarmultBase(spendSecret);
  const viewSecret = hashToScalar(scalarToBytes(spendSecret));
  const viewPublicPoint = scalarmultBase(viewSecret);
  return {
    spendSecret,                       // bigint scalar "a"
    spendPublic: spendPublicPoint.toBytes(), // 32-byte compressed point "A"
    viewSecret,                        // bigint scalar "b"
    viewPublic: viewPublicPoint.toBytes(),   // 32-byte "B"
  };
}

export function randomSeed() {
  return ed.etc.randomBytes(32);
}

// ── Address encoding ────────────────────────────────────────────────────────
/**
 * Standard address bytes: [prefix(1) || A(32) || B(32)] then append a 4-byte
 * checksum = first 4 bytes of keccak256(payload), finally base58. Result is
 * 69 bytes → 95 chars, exactly like a Monero standard address.
 */
export function addressFromKeys(spendPublic, viewPublic, prefix = ADDRESS_PREFIX_STANDARD) {
  const payload = concatBytes(Uint8Array.from([prefix]), spendPublic, viewPublic);
  const checksum = cnFastHash(payload).subarray(0, 4);
  return b58encode(concatBytes(payload, checksum));
}

export function keysFromAddress(address) {
  const raw = b58decode(address);
  // 1 prefix byte + 32 A + 32 B + 4 checksum = 69 bytes → 95 base58 chars.
  if (raw.length !== 69) throw new Error(`bad address length ${raw.length}`);
  const payload = raw.subarray(0, 65);
  const checksum = raw.subarray(65, 69);
  const expected = cnFastHash(payload).subarray(0, 4);
  for (let i = 0; i < 4; i++) if (checksum[i] !== expected[i]) throw new Error('address checksum mismatch');
  return {
    prefix: payload[0],
    spendPublic: payload.subarray(1, 33),
    viewPublic: payload.subarray(33, 65),
  };
}

// ── Stealth / one-time addresses ────────────────────────────────────────────

/**
 * Sender side: create a one-time output key pair for a recipient address.
 * Returns { txPublicKey R = r·G, oneTimeSpendKey P, sharedSecretForSender }.
 * Amounts are NOT hidden here (see docs: RingCT omitted in v0.1).
 */
export function createOutputKeys(recipientSpendPublic, recipientViewPublic, r) {
  const A = ed.Point.fromBytes(recipientSpendPublic);
  const B = ed.Point.fromBytes(recipientViewPublic);
  const rPoint = scalarmultBase(r); // R = r·G  (published in the tx)
  const rB = scalarmultPoint(B, r); // shared secret point ss = r·B
  const hs = hashToScalar(rB.toBytes());
  const P = scalarmultBase(hs).add(A); // P = Hs(r·B)·G + A
  return {
    txPublicKey: rPoint.toBytes(),
    oneTimeSpendKey: P.toBytes(),
  };
}

/**
 * Recipient scanning side: given the published tx public key R and our view
 * secret b, recover whether an output pays us and its one-time spend key:
 *   P' = Hs(b·R)·G + A   must equal the real output key.
 * We return the candidate P so callers can compare against the blockchain.
 */
export function scanOutput(txPublicKey, accountSpendPublic, viewSecret) {
  const R = ed.Point.fromBytes(txPublicKey);
  const A = ed.Point.fromBytes(accountSpendPublic);
  const bR = scalarmultPoint(R, viewSecret); // b·R = b·r·G = r·B ✓
  const hs = hashToScalar(bR.toBytes());
  return scalarmultBase(hs).add(A).toBytes();
}

/**
 * Spending side: recover the one-time private key x for output P:
 *   x = Hs(b·R) + a   where P = x·G.
 */
export function deriveOutputSecret(txPublicKey, viewSecret, spendSecret) {
  const R = ed.Point.fromBytes(txPublicKey);
  const bR = scalarmultPoint(R, viewSecret);
  const hs = hashToScalar(bR.toBytes());
  return modN(hs + spendSecret);
}

/** Public key of a one-time output computed from secrets (sanity check). */
export function outputPublicKeyFromSecret(x) {
  return scalarmultBase(x).toBytes();
}

// ── Formatting helpers ──────────────────────────────────────────────────────
export function formatDNE(picoDNE) {
  const bi = BigInt(picoDNE);
  const whole = bi / COIN;
  const frac = (bi % COIN).toString().padStart(12, '0');
  return `${whole}.${frac.replace(/0+$/, '') || '0'} DNE`;
}

export function parseDNE(str) {
  const m = /^(\d+)(?:\.(\d{1,12}))?$/.exec(str.trim());
  if (!m) throw new Error(`bad amount: ${str}`);
  const whole = BigInt(m[1]) * COIN;
  const frac = BigInt((m[2] ?? '').padEnd(12, '0') || '0');
  return whole + frac;
}
