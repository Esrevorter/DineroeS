/**
 * Canonical serialization for DineroeS consensus objects.
 *
 * Monero uses "Binary Archive" (varint-heavy, little-endian) formats inside
 * Boost-serialized blobs. We mirror the spirit with a simple, fully-specified
 * deterministic byte format so that two nodes always agree on tx/block hashes:
 *
 *   u8/u64      : little-endian fixed width
 *   varint      : 7-bit groups, continuation bit set on all but last byte
 *                 (identical in meaning to Monero's `varint` / LEB128-unsigned)
 *   bytes       : varint length prefix + raw bytes
 *   utf8 string : varint byte-length + UTF-8 bytes
 *
 * Every consensus structure has exactly ONE encoding; hash it with Keccak-256
 * (`cnFastHash`) to get its id. Ambiguity-free by construction.
 */
import { u64LE, concatBytes } from '../crypto/hash.js';

// ── writers ─────────────────────────────────────────────────────────────────
export function wU8(n) {
  if (!Number.isInteger(n) || n < 0 || n > 255) throw new RangeError('u8 out of range: ' + n);
  return Uint8Array.from([n]);
}

export function wU64(n) {
  const v = typeof n === 'bigint' ? n : BigInt(n);
  if (v < 0n || v >= 2n ** 64n) throw new RangeError('u64 out of range: ' + v);
  return u64LE(v);
}

/** Unsigned LEB128 varint, like Monero's epee varint. */
export function wVarint(n) {
  let v = typeof n === 'bigint' ? n : BigInt(n);
  if (v < 0n) throw new RangeError('varint must be non-negative');
  const out = [];
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) byte |= 0x80;
    out.push(byte);
  } while (v > 0n);
  return Uint8Array.from(out);
}

export function wBytes(b) {
  return concatBytes(wVarint(b.length), Uint8Array.from(b));
}

export function wString(s) {
  return wBytes(new TextEncoder().encode(s));
}

/** Fixed-size raw field (no length prefix) — used for 32-byte hashes/points. */
export function wRaw(b) {
  return Uint8Array.from(b);
}

// ── readers ────────────────────────────────────────────────────────────────
export class ByteReader {
  constructor(buf) {
    this.buf = buf instanceof Uint8Array ? buf : Uint8Array.from(buf);
    this.pos = 0;
  }
  u8() {
    const v = this.buf[this.pos];
    if (v === undefined) throw new Error('read past end');
    this.pos++;
    return v;
  }
  u64() {
    let n = 0n;
    for (let i = 0; i < 8; i++) n |= BigInt(this.u8()) << BigInt(8 * i);
    return n;
  }
  varint() {
    let n = 0n;
    let shift = 0n;
    for (;;) {
      const b = this.u8();
      n |= BigInt(b & 0x7f) << shift;
      if ((b & 0x80) === 0) break;
      shift += 7n;
      if (shift > 63n) throw new Error('varint too long');
    }
    return n;
  }
  bytes() {
    const len = Number(this.varint());
    if (this.pos + len > this.buf.length) throw new Error('read past end');
    const out = this.buf.subarray(this.pos, this.pos + len);
    this.pos += len;
    return out;
  }
  string() {
    return new TextDecoder().decode(this.bytes());
  }
  raw(n) {
    if (this.pos + n > this.buf.length) throw new Error('read past end');
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  eof() {
    return this.pos >= this.buf.length;
  }
}
