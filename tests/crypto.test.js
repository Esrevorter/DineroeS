import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
ed.hashes.sha512 = sha512;

import { cnFastHash, hashToScalar, hashToPoint, modN, deriveKeyImage, cnSlowHash, meetsDifficulty, scalarToBytes, bytesToScalarLE } from '../src/crypto/hash.js';
import { keysFromSeed, addressFromKeys, keysFromAddress, createOutputKeys, scanOutput, deriveOutputSecret, randomSeed, parseDNE, formatDNE } from '../src/crypto/keys.js';
import { encode as b58e, decode as b58d } from '../src/crypto/base58.js';
import { signRing, verifyRing, keyImageForOutput, ringSigToHex, ringSigFromHex } from '../src/crypto/ring.js';
import { RING_SIZE, ED25519_SCALAR_ORDER } from '../src/constants.js';

test('keccak matches known vector', () => {
  // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 (original Keccak, not SHA3)
  const h = Buffer.from(cnFastHash(new Uint8Array([]))).toString('hex');
  assert.equal(h, 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
});

test('scalar LE roundtrip', () => {
  const s = 12345678901234567890123n;
  assert.equal(bytesToScalarLE(scalarToBytes(s)), s);
});

test('hashToScalar deterministic and < order after reduce', () => {
  const a = hashToScalar('hello');
  const b = hashToScalar('hello');
  assert.equal(a, b);
  assert.ok(a < ED25519_SCALAR_ORDER);
});

test('hashToPoint lands in prime subgroup', () => {
  const p = hashToPoint('some-output-key-data');
  assert.ok(!p.is0());
  // In the prime-order subgroup: (n-1)*P + P == ZERO, and n*P would be ZERO.
  // noble's multiply rejects n itself, so use n-1 and add P back.
  const q = p.multiply(ED25519_SCALAR_ORDER - 1n).add(p);
  assert.ok(q.is0(), 'point must have order dividing the group order');
  // deterministic
  assert.ok(hashToPoint('some-output-key-data').equals(p));
});

test('base58 roundtrip Monero-style blocks', () => {
  for (const len of [1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 65, 69]) {
    const data = new Uint8Array(len).map((_, i) => (i * 37 + 11) & 0xff);
    const enc = b58e(data);
    const dec = b58d(enc);
    assert.deepEqual(Array.from(dec), Array.from(data), `len ${len}`);
  }
});

test('account keys + address roundtrip', () => {
  const seed = randomSeed();
  const k = keysFromSeed(seed);
  const addr = addressFromKeys(k.spendPublic, k.viewPublic);
  assert.equal(addr.length, 95, 'standard address must be 95 chars like Monero');
  const back = keysFromAddress(addr);
  assert.deepEqual(Array.from(back.spendPublic), Array.from(k.spendPublic));
  assert.deepEqual(Array.from(back.viewPublic), Array.from(k.viewPublic));
});

test('address checksum catches typos', () => {
  const seed = randomSeed();
  const k = keysFromSeed(seed);
  const addr = addressFromKeys(k.spendPublic, k.viewPublic);
  const bad = addr.slice(0, -1) + (addr.endsWith('1') ? '2' : '1');
  assert.throws(() => keysFromAddress(bad));
});

test('stealth address: sender creates, recipient scans, spender derives', () => {
  const seed = randomSeed();
  const acct = keysFromSeed(seed);
  const r = modN(bytesToScalarLE(cnFastHash('random-ephemeral')));
  const out = createOutputKeys(acct.spendPublic, acct.viewPublic, r);
  const scanned = scanOutput(out.txPublicKey, acct.spendPublic, acct.viewSecret);
  assert.deepEqual(Array.from(scanned), Array.from(out.oneTimeSpendKey), 'scan recovers one-time key');
  const x = deriveOutputSecret(out.txPublicKey, acct.viewSecret, acct.spendSecret);
  const P = ed.Point.BASE.multiply(x);
  assert.deepEqual(Array.from(P.toBytes()), Array.from(out.oneTimeSpendKey), 'x*G == P');
});

test('LSAG ring signature verifies, tampering fails', () => {
  const n = RING_SIZE;
  // fabricate a ring: n random keys, we own index 5
  const realIdx = 5;
  const { secretKey: sk } = ed.keygen(); // use raw ed25519 scalar? need scalar form
  // simpler: pick our own scalar x and compute P = x*G
  const x = modN(bytesToScalarLE(cnFastHash('my-secret')));
  const P = ed.Point.BASE.multiply(x);
  const ring = [];
  for (let i = 0; i < n; i++) {
    if (i === realIdx) ring.push(P.toBytes());
    else {
      const xi = modN(bytesToScalarLE(cnFastHash('decoy-' + i)));
      ring.push(ed.Point.BASE.multiply(xi).toBytes());
    }
  }
  const message = cnFastHash('tx-prefix-hash');
  const sig = signRing(message, ring, realIdx, x);
  assert.ok(verifyRing(message, ring, sig), 'valid ring sig must verify');

  // tamper: flip one s value
  const bad = { ...sig, s: [...sig.s] };
  bad.s[0] = modN(bad.s[0] + 1n);
  assert.ok(!verifyRing(message, ring, bad), 'tampered sig must fail');

  // wrong message
  assert.ok(!verifyRing(cnFastHash('other'), ring, sig));

  // sig serializes through hex
  const restored = ringSigFromHex(ringSigToHex(sig));
  assert.ok(verifyRing(message, ring, restored));
});

test('key image is deterministic per output secret', () => {
  const x = modN(bytesToScalarLE(cnFastHash('kix')));
  const P = ed.Point.BASE.multiply(x);
  const ki1 = keyImageForOutput(P.toBytes(), x);
  const ki2 = deriveKeyImage(x, P);
  assert.deepEqual(Array.from(ki1), Array.from(ki2));
});

test('signRing refuses wrong secret for claimed member', () => {
  const x = modN(bytesToScalarLE(cnFastHash('right')));
  const y = modN(bytesToScalarLE(cnFastHash('wrong')));
  const P = ed.Point.BASE.multiply(x);
  const ring = [P.toBytes(), ed.Point.BASE.multiply(y).toBytes()];
  assert.throws(() => signRing(cnFastHash('m'), ring, 0, y));
});

test('cnSlowHash deterministic + difficulty check', () => {
  const input = cnFastHash('block-header');
  const h1 = cnSlowHash(input);
  const h2 = cnSlowHash(input);
  assert.deepEqual(Array.from(h1), Array.from(h2));
  // difficulty 1 always met; huge difficulty almost never
  assert.ok(meetsDifficulty(h1, 1n));
  assert.ok(!meetsDifficulty(h1, 2n ** 255n));
});

test('amount parsing', () => {
  assert.equal(parseDNE('1'), 1_000_000_000_000n);
  assert.equal(parseDNE('0.5'), 500_000_000_000n);
  assert.equal(formatDNE(1_500_000_000_000n), '1.5 DNE');
});
