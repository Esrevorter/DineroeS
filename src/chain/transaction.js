/**
 * DineroeS transactions — Monero's structure, simplified where v0.1 cannot do
 * RingCT (see docs/architecture.md "Privacy model").
 *
 * A DineroeS transaction mirrors cryptonote_transaction:
 *   version, unlock_time, extra, inputs[], outputs[]  → the "prefix"
 *   signatures[] (one LSAG ring signature per input)  → appended after prefix
 *
 * Inputs are "key image spend refs": to spend an output you publish a ring of
 * one-time public keys (mixins + the real one) and an LSAG signature binding a
 * unique key image. The chain rejects any tx whose key image was seen before —
 * that is double-spend prevention without revealing which ring member is real.
 *
 * Outputs are one-time stealth keys P = Hs(r·B)·G + A created from a random
 * per-tx scalar r (published as R = r·G in `extra`). Amounts are visible in
 * v0.1 (RingCT omitted); everything else matches Monero exactly.
 */
import { cnFastHash, concatBytes, bytesToHex, bytesToScalarLE } from '../crypto/hash.js';
import { createOutputKeys } from '../crypto/keys.js';
import { signRing, verifyRing } from '../crypto/ring.js';
import { wU8, wU64, wVarint, wBytes, wRaw, ByteReader } from './serialize.js';
import { RING_SIZE, DEFAULT_UNLOCK_TIME } from '../constants.js';

export const TX_VERSION = 1; // 1 == ring-signature tx (Monero's meaning too)

// ── builders ────────────────────────────────────────────────────────────────

/**
 * Build an unsigned tx prefix. The `extra` field must already contain the
 * per-output ephemeral public keys (TAG_TX_PUBKEY 0x01 || R) — use
 * `assembleExtra()` for that.
 * @param {object} opts
 *  - inputs: [{ ring: Uint8Array[](RING_SIZE) }]   (published decoy set only)
 *  - outputs: [{ amountPico: bigint, key: Uint8Array(32) }]  (one-time keys)
 *  - feePico: bigint
 *  - unlockTime?: number
 */
export function buildTxPrefix({ inputs, outputs, feePico, extra = new Uint8Array(0), unlockTime = DEFAULT_UNLOCK_TIME }) {
  const serializedInputs = inputs.map((inp) => {
    if (inp.ring.length !== RING_SIZE) throw new Error(`ring size must be ${RING_SIZE}`);
    return { ring: inp.ring }; // only the ring is published
  });
  const serializedOutputs = outputs.map((o) => ({ amount: o.amountPico ?? o.amount, key: o.key }));
  return {
    version: TX_VERSION,
    unlockTime,
    inputs: serializedInputs,
    outputs: serializedOutputs,
    extra,
    feePico,
  };
}

/** Create one-time output keys for all recipients with a fresh random scalar r per output. */
export function prepareOutputs(outputs, randFn) {
  return outputs.map((o) => {
    const r = randFn();
    const { txPublicKey, oneTimeSpendKey } = createOutputKeys(o.address.spendPublic, o.address.viewPublic, r);
    return { amountPico: o.amountPico, key: oneTimeSpendKey, txPublicKey, r };
  });
}

/**
 * Assemble the `extra` field from prepared outputs, using Monero's tag scheme:
 * repeated [0x01 || R] entries (TAG_TX_PUBKEY). Optionally prepend a payment
 * id entry [0x00 || 32-byte id] like Monero's TAG_PAYMENT_ID.
 */
export function assembleExtra(preparedOutputs, paymentIdBytes) {
  const parts = [];
  if (paymentIdBytes) {
    parts.push(Uint8Array.from([0x00]), Uint8Array.from(paymentIdBytes));
  }
  for (const o of preparedOutputs) parts.push(Uint8Array.from([0x01]), o.txPublicKey);
  return concatBytes(...parts);
}

// ── serialization (canonical blob) ─────────────────────────────────────────

export function serializeTxPrefix(tx) {
  const parts = [wU8(tx.version), wU64(tx.unlockTime)];
  parts.push(wVarint(tx.inputs.length));
  for (const inp of tx.inputs) {
    parts.push(wVarint(inp.ring.length));
    for (const pk of inp.ring) parts.push(wBytes(pk));
  }
  parts.push(wVarint(tx.outputs.length));
  for (const out of tx.outputs) {
    parts.push(wU64(out.amount));
    parts.push(wBytes(out.key));
  }
  parts.push(wBytes(tx.extra));
  return concatBytes(...parts);
}

export function deserializeTxPrefix(bytes) {
  const r = new ByteReader(bytes);
  const version = r.u8();
  const unlockTime = r.u64();
  const nIn = Number(r.varint());
  const inputs = [];
  for (let i = 0; i < nIn; i++) {
    const n = Number(r.varint());
    const ring = [];
    for (let j = 0; j < n; j++) ring.push(r.bytes());
    inputs.push({ ring });
  }
  const nOut = Number(r.varint());
  const outputs = [];
  for (let i = 0; i < nOut; i++) {
    const amount = r.u64();
    const key = r.bytes();
    outputs.push({ amount, key });
  }
  const extra = r.bytes();
  return { version, unlockTime, inputs, outputs, extra };
}

/** Full tx = prefix || fee(u64) || sigCount(varint) || signatures. */
export function serializeTx(tx) {
  // Canonical signature encoding: keyImage(32 bytes) || c0(32 LE) || sCount(varint) || s[i](32 LE each)
  const p2 = [serializeTxPrefix(tx), wU64(tx.feePico), wVarint(tx.signatures.length)];
  for (const sig of tx.signatures) {
    p2.push(wRaw(sig.keyImage));
    p2.push(wRaw(scalarBytes(sig.c0)));
    p2.push(wVarint(sig.s.length));
    for (const s of sig.s) p2.push(wRaw(scalarBytes(s)));
  }
  return concatBytes(...p2);
}

/** Parse a full serialized tx back into its object form (JSON-safe bigints stay bigint). */
export function deserializeTx(bytes) {
  const r = new ByteReader(bytes);
  const version = r.u8();
  const unlockTime = r.u64();
  const nIn = Number(r.varint());
  const inputs = [];
  for (let i = 0; i < nIn; i++) {
    const n = Number(r.varint());
    const ring = [];
    for (let j = 0; j < n; j++) ring.push(Uint8Array.from(r.bytes()));
    inputs.push({ ring });
  }
  const nOut = Number(r.varint());
  const outputs = [];
  for (let i = 0; i < nOut; i++) {
    const amount = r.u64();
    const key = Uint8Array.from(r.bytes());
    outputs.push({ amount, key });
  }
  const extra = Uint8Array.from(r.bytes());
  const feePico = r.u64();
  const nSig = Number(r.varint());
  const signatures = [];
  for (let i = 0; i < nSig; i++) {
    const keyImage = Uint8Array.from(r.raw(32)); // fixed-size field, mirrors wRaw in serializeTx
    const c0 = bytesToScalarLE(r.raw(32));
    const nS = Number(r.varint());
    const s = [];
    for (let j = 0; j < nS; j++) s.push(bytesToScalarLE(r.raw(32)));
    signatures.push({ keyImage, c0, s });
  }
  if (!r.eof()) throw new Error('trailing bytes in tx blob');
  return { version, unlockTime, inputs, outputs, extra, feePico, signatures };
}

function scalarBytes(s) {
  // little-endian 32 bytes
  const out = new Uint8Array(32);
  let n = BigInt(s);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

export function txId(tx) {
  return bytesToHex(cnFastHash(serializeTx(tx)));
}

// ── signing / verification ─────────────────────────────────────────────────

/**
 * Sign a tx. perInputSecrets[i] = { realIndex, x } — the sender-only data that
 * never goes on-chain. The unsigned prefix must already carry `extra` (from
 * assembleExtra) and the final output keys.
 */
export function signTx(unsigned, perInputSecrets) {
  if (perInputSecrets.length !== unsigned.inputs.length) throw new Error('secrets/input count mismatch');
  const tx = { ...unsigned, signatures: [] };
  const prefixBlob = serializeTxPrefix(tx);
  const message = cnFastHash(prefixBlob);
  for (let i = 0; i < tx.inputs.length; i++) {
    const inp = tx.inputs[i];
    const sec = perInputSecrets[i];
    const sig = signRing(message, inp.ring, sec.realIndex, sec.x);
    tx.signatures.push({ keyImage: sig.keyImage, c0: sig.c0, s: sig.s });
  }
  return tx;
}

/**
 * Verify all consensus rules that don't need chain state:
 * structure, ring sizes, LSAG signature validity, no duplicate key images
 * within the tx. Returns { ok, reason }.
 */
export function verifyTxStructure(tx) {
  try {
    if (tx.version !== TX_VERSION) return { ok: false, reason: 'bad version' };
    if (!tx.inputs?.length || !tx.outputs?.length) return { ok: false, reason: 'empty inputs/outputs' };
    if (tx.signatures.length !== tx.inputs.length) return { ok: false, reason: 'sig/input count mismatch' };
    const message = cnFastHash(serializeTxPrefix(tx));
    const seenImages = new Set();
    for (let i = 0; i < tx.inputs.length; i++) {
      const inp = tx.inputs[i];
      if (inp.ring.length !== RING_SIZE) return { ok: false, reason: 'bad ring size' };
      const hexImg = bytesToHex(tx.signatures[i].keyImage);
      if (seenImages.has(hexImg)) return { ok: false, reason: 'duplicate key image in tx' };
      seenImages.add(hexImg);
      const ok = verifyRing(message, inp.ring, tx.signatures[i]);
      if (!ok) return { ok: false, reason: `bad ring signature on input ${i}` };
    }
    // balance check needs amounts visible (v0.1): sum(in) >= sum(out) + fee
    const inSum = tx.inputAmountTotal ?? null;
    if (inSum !== null) {
      const outSum = tx.outputs.reduce((a, o) => a + o.amount, 0n);
      if (inSum < outSum + tx.feePico) return { ok: false, reason: 'unbalanced tx' };
      if (inSum > outSum + tx.feePico) return { ok: false, reason: 'change must be explicit output' };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: 'malformed tx: ' + e.message };
  }
}
