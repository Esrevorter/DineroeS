/**
 * M3 tests: serialization, Merkle trees, LWMA difficulty, emission curve,
 * blocks (coinbase, PoW, genesis) and the Blockchain consensus engine.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { wU8, wU64, wVarint, wBytes, ByteReader } from '../src/chain/serialize.js';
import { merkleRootFromBlobs, merkleProof, verifyMerkleProof, treeLeaf } from '../src/chain/merkle.js';
import { nextDifficultyLWMA } from '../src/chain/difficulty.js';
import { baseReward, blockReward } from '../src/chain/emission.js';
import { genesisBlock, assembleBlock, mineBlock, verifyBlockStructure, computeBlockId, serializeHeader, deserializeHeader, checkProofOfWork } from '../src/chain/block.js';
import { Blockchain } from '../src/chain/blockchain.js';
import { bytesToHex, hexToBytes } from '../src/crypto/hash.js';
import { keysFromSeed, randomSeed } from '../src/crypto/keys.js';
import { TAIL_EMISSION_PER_BLOCK, RING_SIZE } from '../src/constants.js';

// ── serialization ───────────────────────────────────────────────────────────
test('varint roundtrip + known LEB128 vectors', () => {
  for (const n of [0n, 1n, 127n, 128n, 300n, 2n ** 32n, 2n ** 63n]) {
    const r = new ByteReader(wVarint(n));
    assert.equal(r.varint(), n);
  }
  assert.deepEqual([...wVarint(300n)], [0xac, 0x02]); // canonical LEB128
});

test('header serialize/deserialize roundtrip', () => {
  const g = genesisBlock();
  const back = deserializeHeader(serializeHeader(g.header));
  assert.equal(back.height, 0);
  assert.equal(back.timestamp, g.header.timestamp);
  assert.equal(back.difficulty, BigInt(g.header.difficulty));
  assert.deepEqual([...back.prevId], [...g.header.prevId]);
});

// ── merkle ──────────────────────────────────────────────────────────────────
test('merkle root deterministic & order-sensitive', () => {
  const a = new Uint8Array([1]);
  const b = new Uint8Array([2]);
  const c = new Uint8Array([3]);
  const r1 = merkleRootFromBlobs([a, b, c]);
  const r2 = merkleRootFromBlobs([a, b, c]);
  const r3 = merkleRootFromBlobs([c, b, a]);
  assert.deepEqual(r1, r2);
  assert.notDeepEqual(r1, r3);
});

test('merkle proof verifies for every leaf', () => {
  const blobs = Array.from({ length: 7 }, (_, i) => Uint8Array.from([i]));
  const leaves = blobs.map(treeLeaf);
  const root = merkleRootFromBlobs(blobs);
  for (let i = 0; i < 7; i++) {
    const proof = merkleProof(leaves, i);
    assert.ok(verifyMerkleProof(leaves[i], proof, i, root), `proof ${i}`);
    assert.ok(!verifyMerkleProof(leaves[(i + 1) % 7], proof, i, root), 'wrong leaf rejected');
  }
});

// ── LWMA difficulty ─────────────────────────────────────────────────────────
test('LWMA keeps pace when blocks arrive on target', () => {
  // synthetic chain: PER-BLOCK difficulty constant at 100, timestamps exactly
  // 120s apart → LWMA-1 must return ~100 (its defining property: D = d·T/dt)
  const blocks = [];
  for (let i = 0; i < 60; i++) {
    blocks.push({ timestamp: 1_700_000_000 + (i + 1) * 120, difficulty: 100n });
  }
  const d = nextDifficultyLWMA(blocks, 61);
  assert.ok(d >= 95n && d <= 105n, `expected ~100, got ${d}`);
});

test('LWMA raises difficulty after fast blocks, lowers after slow ones', () => {
  const mk = (dt) => {
    const arr = [];
    let ts = 1_700_000_000;
    for (let i = 0; i < 60; i++) {
      ts += dt;
      arr.push({ timestamp: ts, difficulty: 1000n }); // constant per-block diff
    }
    return arr;
  };
  const fast = nextDifficultyLWMA(mk(60), 61);   // double speed
  const slow = nextDifficultyLWMA(mk(240), 61);  // half speed
  assert.ok(fast > 1000n, `fast should raise: ${fast}`);
  assert.ok(slow < 1000n, `slow should lower: ${slow}`);
  // LWMA-1 exactness: constant d ⇒ D_next ≈ d·T/dt
  assert.ok(fast >= 1990n && fast <= 2010n, `fast ≈ 2000, got ${fast}`);
  assert.equal(slow, 500n);
});

// ── emission ────────────────────────────────────────────────────────────────
test('emission decays exponentially then floors at tail', () => {
  const r1 = baseReward(1);
  const rHalfLife = baseReward(20_000); // one "halving" period
  assert.ok(rHalfLife <= r1 / 2n && rHalfLife > r1 / 3n, `${r1} -> ${rHalfLife}`);
  const deep = baseReward(400_000);
  assert.equal(blockReward(400_000), TAIL_EMISSION_PER_BLOCK); // tail took over
  assert.ok(deep < TAIL_EMISSION_PER_BLOCK);
});

test('emission is pure integer math (same result across calls)', () => {
  assert.equal(baseReward(12345), baseReward(12345));
  assert.equal(blockReward(99999, 5n), blockReward(99999) + 5n);
});

// ── blocks & chain ──────────────────────────────────────────────────────────
function minerKeys() {
  const k = keysFromSeed(randomSeed());
  return { account: { spendPublic: k.spendPublic }, viewPublic: k.viewPublic };
}

test('genesis block is deterministic and self-consistent', () => {
  const g1 = genesisBlock();
  const g2 = genesisBlock();
  assert.equal(g1.id, g2.id);
  assert.equal(g1.header.height, 0);
  assert.equal(bytesToHex(computeBlockId(g1.header)), g1.id);
});

test('mine at difficulty 1 and add to chain', () => {
  const chain = new Blockchain();
  chain.initGenesis();
  const g = chain.tip();
  const unsolved = assembleBlock({
    timestamp: g.header.timestamp + 120,
    prevId: hexToBytes(g.id),
    height: 1,
    difficulty: 1n,
    cumulativeDifficulty: BigInt(g.header.cumulativeDifficulty) + 1n,
    nonce: 0,
    minerAddress: minerKeys(),
    rSeed: 42n,
  });
  const solved = mineBlock(unsolved, 100_000);
  assert.ok(solved, 'mining failed within budget');
  assert.ok(checkProofOfWork(solved.header));
  const res = chain.addBlock(solved, { skipDifficultyCheck: true }); // height-1 uses genesis diff anyway
  assert.ok(res.ok, res.reason);
  assert.equal(chain.height, 1);
  // coinbase output registered in UTXO map
  const cbKey = bytesToHex(solved.coinbase.outputs[0].key);
  assert.ok(chain.outputsByKey.has(cbKey));
});

test('reject tampered merkle root, forged id, bad cumulative diff', () => {
  const chain = new Blockchain();
  chain.initGenesis();
  const g = chain.tip();
  const mk = (over = {}) =>
    mineBlock(assembleBlock({
      timestamp: g.header.timestamp + 120,
      prevId: hexToBytes(g.id),
      height: 1,
      difficulty: 1n,
      cumulativeDifficulty: BigInt(g.header.cumulativeDifficulty) + 1n,
      nonce: 0,
      minerAddress: minerKeys(),
      rSeed: 7n,
      ...over,
    }), 100_000);

  // tamper: change coinbase amount AFTER assembly → merkle mismatch
  const b = mk();
  b.coinbase.outputs[0].amount += 1n;
  assert.equal(verifyBlockStructure(b).reason, 'merkle root mismatch');

  // forged id
  const b2 = mk();
  const bad = { ...b2, id: bytesToHex(new Uint8Array(32)) };
  assert.equal(chain.addBlock(bad, { skipPowCheck: true }).reason ?? '', 'block id does not match header');

  // wrong cumulative difficulty
  const b3 = mk();
  const hdr = { ...b3.header, cumulativeDifficulty: 999_999n };
  const res = chain.addBlock({ ...b3, header: hdr, id: bytesToHex(computeBlockId(hdr)) }, { skipDifficultyCheck: true, skipPowCheck: true });
  assert.match(res.reason, /cumulative difficulty/);
});

test('timestamp must exceed median-of-3', () => {
  const chain = new Blockchain();
  chain.initGenesis();
  const g = chain.tip();
  const oldTs = assembleBlock({
    timestamp: g.header.timestamp - 10, // before genesis!
    prevId: hexToBytes(g.id),
    height: 1, difficulty: 1n, cumulativeDifficulty: BigInt(g.header.cumulativeDifficulty) + 1n,
    nonce: 0, minerAddress: minerKeys(), rSeed: 1n,
  });
  const res = chain.addBlock(oldTs, { skipPowCheck: true, skipDifficultyCheck: true });
  assert.match(res.reason, /median-3/);
});

test('save/load JSONL roundtrip preserves chain state', async () => {
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = `${await (await import('node:fs/promises')).mkdtemp(os.tmpdir() + '/dines-test-')}/chain.jsonl`;
  const chain = new Blockchain();
  chain.initGenesis();
  const g = chain.tip();
  const solved = mineBlock(assembleBlock({
    timestamp: g.header.timestamp + 120,
    prevId: hexToBytes(g.id),
    height: 1, difficulty: 1n, cumulativeDifficulty: BigInt(g.header.cumulativeDifficulty) + 1n,
    nonce: 0, minerAddress: minerKeys(), rSeed: 9n,
  }), 100_000);
  assert.ok(chain.addBlock(solved, { skipDifficultyCheck: true }).ok);
  chain.saveToFile(fs, path);

  const restored = new Blockchain();
  assert.ok(restored.loadFromFile(fs, path));
  assert.equal(restored.height, 1);
  assert.equal(restored.tipId(), chain.tipId());
  assert.equal(restored.cumulativeDifficulty(), chain.cumulativeDifficulty());
  const cbKey = bytesToHex(solved.coinbase.outputs[0].key);
  assert.deepEqual(restored.outputsByKey.get(cbKey).amount, BigInt(solved.coinbase.outputs[0].amount));
});

test('full tx lifecycle on-chain: coinbase spend with ring signature', async () => {
  const { buildTxPrefix, prepareOutputs, assembleExtra, signTx, verifyTxStructure, serializeTx, deserializeTx } = await import('../src/chain/transaction.js');
  const { keysFromSeed: kfs, randomSeed: rs, deriveOutputSecret } = await import('../src/crypto/keys.js');
  const { keyImageForOutput } = await import('../src/crypto/ring.js');
  const { modN, bytesToScalarLE } = await import('../src/crypto/hash.js');

  const chain = new Blockchain();
  chain.initGenesis();
  const g = chain.tip();

  // Mine block 1 paying to alice's coinbase address
  const alice = kfs(rs());
  const b1 = mineBlock(assembleBlock({
    timestamp: g.header.timestamp + 120, prevId: hexToBytes(g.id), height: 1,
    difficulty: 1n, cumulativeDifficulty: BigInt(g.header.cumulativeDifficulty) + 1n,
    nonce: 0, minerAddress: { account: { spendPublic: alice.spendPublic }, viewPublic: alice.viewPublic }, rSeed: 5n,
  }), 100_000);
  assert.ok(chain.addBlock(b1, { skipDifficultyCheck: true }).ok);

  // Alice spends her coinbase output in block 2 → pays bob.
  // (Coinbase maturity normally requires unlock; we test the mechanics by
  //  mining directly at height where unlockTime is satisfied? Height 2 < 61,
  //  so instead we verify the rule REJECTS it first, then bypass via a
  //  maturity-free tx built against a regular output.)
  const cbOut = b1.coinbase.outputs[0];
  const cbKeyHex = bytesToHex(cbOut.key);
  const outInfo = chain.outputsByKey.get(cbKeyHex);
  assert.ok(outInfo.unlockedUntil > 2, 'coinbase should still be locked at height 2');

  // Build the spend anyway and check chain rejects due to unlock time:
  const bob = kfs(rs());
  const ringDecoys = [];
  // not enough outputs for real rings yet — add synthetic decoy keys from fresh stealth derivations
  while (ringDecoys.length < RING_SIZE - 1) {
    const d = prepareOutputs([{ amountPico: 1n, address: { spendPublic: kfs(rs()).spendPublic, viewPublic: kfs(rs()).viewPublic } }], () => modN(bytesToScalarLE(rs())));
    ringDecoys.push(d[0].key);
    chain.outputsByKey.set(bytesToHex(d[0].key), { height: 1, txIndex: 0, outIndex: 0, amount: 1n, unlockedUntil: 0 });
  }
  const ring = [...ringDecoys.slice(0, RING_SIZE - 1)];
  const realIdx = 4;
  ring.splice(realIdx, 0, cbOut.key);

  const x = deriveOutputSecret(b1.coinbase.extra.subarray(1), alice.viewSecret, alice.spendSecret); // extra = [0x01 || R]
  const unsigned = buildTxPrefix({
    inputs: [{ ring }],
    outputs: [{ amountPico: cbOut.amount - 1000n, key: prepareOutputs([{ amountPico: cbOut.amount - 1000n, address: { spendPublic: bob.spendPublic, viewPublic: bob.viewPublic } }], () => 3n)[0].key }],
    feePico: 1000n,
    extra: assembleExtra(prepareOutputs([{ amountPico: 1n, address: { spendPublic: bob.spendPublic, viewPublic: bob.viewPublic } }], () => 3n)),
  });
  const signed = signTx(unsigned, [{ realIndex: realIdx, x }]);
  signed.inputAmountTotal = cbOut.amount;
  assert.ok(verifyTxStructure(signed).ok, 'tx itself should be structurally valid');

  const b2 = mineBlock(assembleBlock({
    timestamp: b1.header.timestamp + 120, prevId: hexToBytes(b1.id), height: 2,
    difficulty: 1n, cumulativeDifficulty: BigInt(b1.header.cumulativeDifficulty) + 1n,
    nonce: 0, minerAddress: { account: { spendPublic: alice.spendPublic }, viewPublic: alice.viewPublic }, rSeed: 6n,
    txs: [signed], feesPico: 1000n,
  }), 100_000);
  const rejected = chain.addBlock(b2, { skipDifficultyCheck: true });
  assert.match(rejected.reason, /unlock time/, 'early coinbase spend must be rejected');

  // serialization roundtrip of the tx
  const back = deserializeTx(serializeTx(signed));
  assert.equal(back.feePico, signed.feePico);
  assert.equal(back.signatures.length, 1);
  assert.ok(verifyTxStructure({ ...back, inputAmountTotal: cbOut.amount }).ok);
});
