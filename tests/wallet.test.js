/**
 * Wallet tests: address roundtrip, view-key scanning, balance, and a full
 * spend flow through the consensus engine (coinbase maturity → transfer →
 * double-spend rejection).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { Wallet } from '../src/wallet/wallet.js';
import { Blockchain } from '../src/chain/blockchain.js';
import { assembleBlock, mineBlock } from '../src/chain/block.js';
import { randomSeed, keysFromAddress, deriveOutputSecret } from '../src/crypto/keys.js';
import { hexToBytes, bytesToHex } from '../src/crypto/hash.js';
import { verifyTxStructure, serializeTx, deserializeTx, buildTxPrefix, prepareOutputs, assembleExtra, signTx } from '../src/chain/transaction.js';
import { COINBASE_MATURITY, RING_SIZE } from '../src/constants.js';

function mineNext(chain, minerWallet, prev, tsOffset = 120, txs = [], feesPico = 0n, rSeed = 7n) {
  const solved = mineBlock(assembleBlock({
    timestamp: prev.header.timestamp + tsOffset,
    prevId: hexToBytes(prev.id),
    height: prev.header.height + 1,
    difficulty: 1n,
    cumulativeDifficulty: BigInt(prev.header.cumulativeDifficulty) + 1n,
    nonce: 0,
    minerAddress: { account: { spendPublic: minerWallet.spendPublic }, viewPublic: minerWallet.viewPublic },
    rSeed,
    txs,
    feesPico,
  }), 200_000);
  assert.ok(solved, 'mining failed within maxTries');
  const res = chain.addBlock(solved, { skipDifficultyCheck: true });
  assert.ok(res.ok, `addBlock failed: ${res.reason}`);
  return solved;
}

test('address encode/decode roundtrip via wallet', () => {
  const w = new Wallet(randomSeed());
  const dec = keysFromAddress(w.getAddress());
  assert.deepEqual([...dec.spendPublic], [...w.spendPublic]);
  assert.deepEqual([...dec.viewPublic], [...w.viewPublic]);
  // deterministic for same seed
  const w2 = new Wallet(w.seed);
  assert.equal(w2.getAddress(), w.getAddress());
});

test('wallet scans coinbase with view key only and reports balance', () => {
  const chain = new Blockchain();
  chain.initGenesis();
  const miner = new Wallet(randomSeed());
  let prev = chain.tip();
  // Mine past coinbase maturity so at least one reward is spendable.
  for (let i = 0; i < COINBASE_MATURITY + 1; i++) {
    prev = mineNext(chain, miner, prev, 120, [], 0n, BigInt(i + 1));
  }
  const found = miner.scanChain(chain);
  assert.equal(found, COINBASE_MATURITY + 1, 'should find every mined coinbase output');
  // Idempotent rescan finds nothing new.
  assert.equal(miner.scanChain(chain), 0);
  assert.equal(miner.balancePico(), sumOutputs(miner));
  const avail = miner.availableOutputs(chain.height);
  assert.ok(avail.length >= 1, 'matured coinbases available at tip height');
  // The most recent block's coinbase is still locked (unlockTime = h+60).
  const latestLocked = [...miner.outputs.values()].filter((o) => o.unlockedUntil > chain.height);
  assert.ok(latestLocked.length >= 1, 'recent coinbase must still be locked');
});

function sumOutputs(w) {
  let s = 0n;
  for (const o of w.outputs.values()) s += o.amount;
  return s;
}

test('full transfer: miner pays alice, alice pays bob, double spend rejected', async () => {
  const chain = new Blockchain();
  chain.initGenesis();
  const miner = new Wallet(randomSeed());
  let prev = chain.tip();
  for (let i = 0; i < COINBASE_MATURITY + 1; i++) {
    prev = mineNext(chain, miner, prev, 120, [], 0n, BigInt(i + 1));
  }
  miner.scanChain(chain);

  const alice = new Wallet(randomSeed());
  const bob = new Wallet(randomSeed());

  // v0.1 has visible amounts and binds each DECLARED input amount to the ONE
  // ring member sharing that amount — so a wallet spend needs its source
  // output's amount to be unique among live outputs, AND its ring must not
  // contain any other member with that same amount (else binding is
  // ambiguous). All early coinbases pay the SAME base reward (piecewise-
  // constant emission curve), so we bootstrap uniqueness with one legitimate
  // trick: a block carrying a real tx collects its fee into the coinbase
  // (reward = base + fee) — an amount seen nowhere else. The bootstrap tx
  // itself is a valid miner→miner self-payment whose input total is NOT
  // declared: per #tryApplyTxs, an undeclared total skips binding/balance
  // enforcement (v0.1 escape hatch until RingCT lands). Its key image still
  // permanently marks the seed output spent.
  const fee = 1_000_000n; // pDNE per transfer

  /** Pick `count` live-output decoys excluding `excludeHex`, all with an
   *  amount different from `avoidAmount` (prevents binding ambiguity). */
  function pickSafeDecoys(excludeHex, avoidAmount, count) {
    const keys = [...chain.outputsByKey.keys()].filter(
      (k) => k !== excludeHex && BigInt(chain.outputsByKey.get(k).amount) !== avoidAmount,
    );
    if (keys.length < count) throw new Error(`not enough non-colliding decoys (${keys.length}/${count})`);
    const picked = new Set();
    while (picked.size < count) picked.add(keys[Math.floor(Math.random() * keys.length)]);
    return [...picked];
  }

  const mkSelfPay = (sourceOut, rScalar) => {
    const x = deriveOutputSecret(sourceOut.txPublicKey, miner.viewSecret, miner.spendSecret);
    const decoys = pickSafeDecoys(sourceOut.keyHex, sourceOut.amount, RING_SIZE - 1);
    const ring = decoys.map(hexToBytes);
    const realIdx = 2;
    ring.splice(realIdx, 0, sourceOut.key);
    // Recipient = the wallet's own address parsed from base58 (a hand-built
    // {spendPublic} object without viewPublic would crash createOutputKeys).
    const minerAccount = keysFromAddress(miner.getAddress());
    const prepared = prepareOutputs([{ amountPico: sourceOut.amount - 1n, address: minerAccount }], () => rScalar);
    const unsigned = buildTxPrefix({
      inputs: [{ ring }],
      outputs: prepared.map((p) => ({ amountPico: p.amountPico, key: p.key })),
      feePico: 1n,
      extra: assembleExtra(prepared),
    });
    return signTx(unsigned, [{ realIndex: realIdx, x }]); // deliberately no inputAmountTotal
  };

  // Block X: self-pay burning 1 pico. Its coinbase pays base+1 (unique) and
  // its self-output pays base-1 (also unique). The only other differently-
  // valued live outputs are the genesis coinbase (no outputs — height 0 pays
  // nothing) and… none: every other coinbase pays exactly `base`. So the
  // safe-decoy pool for spending X's coinbase is the set of base-reward
  // coinbases (amount ≠ base+1) plus X's own base-1 self-output. Plenty.
  const seedOut = miner.availableOutputs(chain.height)[0];
  assert.ok(seedOut, 'need a matured coinbase to bootstrap');
  prev = mineNext(chain, miner, prev, 120, [mkSelfPay(seedOut, 5n)], 0n, 99n);
  await new Promise((r) => setTimeout(r, 5));
  const heightX = prev.header.height;
  const uniqueAmount = prev.coinbase.outputs[0].amount; // base + 1, seen once

  // Mine forward until X's coinbase matures, then spend it → alice.
  const payAlice = uniqueAmount - fee;
  while (chain.height < heightX + COINBASE_MATURITY) {
    prev = mineNext(chain, miner, prev, 120, [], 0n, BigInt(heightX + 1000 + chain.blocks.length));
    await new Promise((r) => setTimeout(r, 5));
  }
  miner.scanChain(chain);
  // Build tx1 manually so its ring avoids any member with amount ==
  // uniqueAmount (only X's coinbase itself has it — excluded as decoy).
  const src1 = miner.availableOutputs(chain.height).find((o) => o.amount === uniqueAmount);
  assert.ok(src1, 'unique coinbase must be matured & available');
  const x1 = deriveOutputSecret(src1.txPublicKey, miner.viewSecret, miner.spendSecret);
  const aliceAccount = keysFromAddress(alice.getAddress());
  const prep1 = prepareOutputs([{ amountPico: payAlice, address: aliceAccount }], () => 7n);
  const ring1 = pickSafeDecoys(src1.keyHex, uniqueAmount, RING_SIZE - 1).map(hexToBytes);
  const realIdx1 = 4;
  ring1.splice(realIdx1, 0, src1.key);
  const tx1 = signTx(
    buildTxPrefix({
      inputs: [{ ring: ring1 }],
      outputs: prep1.map((p) => ({ amountPico: p.amountPico, key: p.key })),
      feePico: fee,
      extra: assembleExtra(prep1),
    }),
    [{ realIndex: realIdx1, x: x1 }],
  );
  tx1.inputAmountTotal = uniqueAmount;
  assert.ok(verifyTxStructure(tx1).ok, `tx1 invalid: ${verifyTxStructure(tx1).reason}`);
  assert.equal(tx1.inputs[0].ring.length, RING_SIZE);
  assert.equal(tx1.inputAmountTotal, uniqueAmount);
  mineNext(chain, miner, prev, 120, [tx1], fee, 101n);
  prev = chain.tip();
  await new Promise((r) => setTimeout(r, 5));

  alice.scanChain(chain);
  assert.equal(alice.balancePico(), payAlice, 'alice received exactly the payment');

  // ── alice → bob: spend her single (globally unique-amount) input, no change ──
  const src2 = alice.availableOutputs(chain.height)[0];
  assert.equal(src2.amount, payAlice);
  const x2 = deriveOutputSecret(src2.txPublicKey, alice.viewSecret, alice.spendSecret);
  const bobAccount = keysFromAddress(bob.getAddress());
  const prep2 = prepareOutputs([{ amountPico: payAlice - fee, address: bobAccount }], () => 9n);
  const ring2 = pickSafeDecoys(src2.keyHex, payAlice, RING_SIZE - 1).map(hexToBytes);
  const realIdx2 = 1;
  ring2.splice(realIdx2, 0, src2.key);
  const tx2 = signTx(
    buildTxPrefix({
      inputs: [{ ring: ring2 }],
      outputs: prep2.map((p) => ({ amountPico: p.amountPico, key: p.key })),
      feePico: fee,
      extra: assembleExtra(prep2),
    }),
    [{ realIndex: realIdx2, x: x2 }],
  );
  tx2.inputAmountTotal = payAlice;
  assert.ok(verifyTxStructure(tx2).ok, `tx2 invalid: ${verifyTxStructure(tx2).reason}`);
  mineNext(chain, miner, prev, 120, [tx2], fee, 102n);
  prev = chain.tip();
  await new Promise((r) => setTimeout(r, 5));

  bob.scanChain(chain);
  assert.equal(bob.balancePico(), payAlice - fee, 'bob received payment minus fee');
  assert.equal(alice.balancePico(), 0n, 'alice spent everything');

  // ── double spend: rebuild an identical-looking tx from alice's now-spent output ──
  // Re-derive her original output & secret directly (simulating a malicious replay).
  const spentOut = [...alice.outputs.values()][0];
  const xd = deriveOutputSecret(spentOut.txPublicKey, alice.viewSecret, alice.spendSecret);
  const evilPrepared = prepareOutputs([{ amountPico: 1n, address: bobAccount }], () => 42n);
  const evilRing = pickSafeDecoys(bytesToHex(spentOut.key), spentOut.amount, RING_SIZE - 1).map(hexToBytes);
  evilRing.splice(3, 0, spentOut.key);
  const evil = signTx(
    buildTxPrefix({
      inputs: [{ ring: evilRing }],
      outputs: evilPrepared.map((p) => ({ amountPico: p.amountPico, key: p.key })),
      feePico: 1n,
      extra: assembleExtra(evilPrepared),
    }),
    [{ realIndex: 3, x: xd }],
  );
  evil.inputAmountTotal = spentOut.amount;
  const rejected = chain.addBlock(assembleBlock({
    timestamp: prev.header.timestamp + 120,
    prevId: hexToBytes(prev.id),
    height: prev.header.height + 1,
    difficulty: 1n,
    cumulativeDifficulty: BigInt(prev.header.cumulativeDifficulty) + 1n,
    nonce: 0,
    minerAddress: { account: { spendPublic: miner.spendPublic }, viewPublic: miner.viewPublic },
    rSeed: 103n,
    txs: [evil],
    feesPico: 1n,
  }), { skipDifficultyCheck: true, skipPowCheck: true });
  assert.match(rejected.reason, /double spend/, 'replayed key image must be rejected');

  // ── wire roundtrip: serialize → deserialize → still structurally valid ──
  const back = deserializeTx(serializeTx(tx1));
  assert.equal(back.feePico, tx1.feePico);
  assert.ok(verifyTxStructure({ ...back, inputAmountTotal: tx1.inputAmountTotal }).ok);
});
