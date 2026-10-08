/**
 * DineroeS base58 encoding — byte-compatible in spirit with Monero's
 * `src/cryptonote_basic/cryptonote_format_utils.cpp`: the byte string is
 * processed in 8-byte blocks; each full block encodes to exactly 11 base58
 * characters (zero-padded), and a partial tail of n bytes encodes to a fixed
 * shorter length from Monero's table. This is what makes Monero standard
 * addresses exactly 95 characters (69 bytes → 8×11 + 7).
 */

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZ'; // no 0, O, I, l (Bitcoin/Monero alphabet)
const BASE = 58n;
const FULL_BLOCK_BYTES = 8;
const FULL_BLOCK_CHARS = 11;

// tail: n bytes ↔ m chars (Monero's table)
const ENCODED_BLOCK_SIZES = [0, 2, 3, 5, 6, 7, 9, 10, 11]; // index = byte count
const DECODED_BLOCK_SIZES = [0, 1, 2, 3, 4, 5, 6, 7, 8];   // index = char count

function bytesToBig(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

function bigToBytes(num, size) {
  const out = new Uint8Array(size);
  let n = num;
  for (let i = size - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  if (n !== 0n) throw new Error('base58 block overflow');
  return out;
}

function encodeBlock(num, chars) {
  const out = new Array(chars);
  let n = num;
  for (let i = chars - 1; i >= 0; i--) {
    out[i] = ALPHABET[Number(n % BASE)];
    n = n / BASE; // BigInt division truncates toward zero; n >= 0 here
  }
  if (n !== 0n) throw new Error('base58 block overflow during encode');
  return out.join('');
}

function decodeBlock(str) {
  let n = 0n;
  for (const ch of str) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error(`Invalid base58 character: ${ch}`);
    n = n * BASE + BigInt(idx);
  }
  return n;
}

/** Encode bytes → Monero-style padded base58 string. */
export function encode(bytes) {
  const buf = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  let out = '';
  const fullBlocks = Math.floor(buf.length / FULL_BLOCK_BYTES);
  for (let i = 0; i < fullBlocks; i++) {
    out += encodeBlock(bytesToBig(buf.subarray(i * 8, i * 8 + 8)), FULL_BLOCK_CHARS);
  }
  const rem = buf.subarray(fullBlocks * FULL_BLOCK_BYTES);
  if (rem.length > 0) {
    out += encodeBlock(bytesToBig(rem), ENCODED_BLOCK_SIZES[rem.length]);
  }
  return out;
}

/** Decode Monero-style padded base58 string → bytes. Inverse of encode(). */
export function decode(str) {
  const chunks = [];
  let pos = 0;
  while (str.length - pos >= FULL_BLOCK_CHARS) {
    chunks.push(bigToBytes(decodeBlock(str.slice(pos, pos + FULL_BLOCK_CHARS)), FULL_BLOCK_BYTES));
    pos += FULL_BLOCK_CHARS;
  }
  const remaining = str.length - pos;
  if (remaining > 0) {
    const byteLen = DECODED_BLOCK_SIZES[remaining];
    if (!byteLen) throw new Error(`Invalid base58 tail length ${remaining}`);
    chunks.push(bigToBytes(decodeBlock(str.slice(pos)), byteLen));
  }
  return Uint8Array.concat ? concatAll(chunks) : merge(chunks);
}

function concatAll(chunks) {
  return merge(chunks);
}

function merge(chunks) {
  const total = chunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}
