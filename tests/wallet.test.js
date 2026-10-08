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
import { keyImageForOutput } from '../src/crypto/ring.js';
import { verifyTxStructure, serializeTx, deserializeTx, buildTxPrefix, prepareOutputs, assembleExtra, signTx } from '../src/chain/transaction.js';
import { COINBASE_MATURITY, RING_SIZE } from '../src/constants.js';
import { baseReward } from '../src/chain/emission.js';

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
  const alice = new Wallet(randomSeed());
  const bob = new Wallet(randomSeed());
  const sleep = () => new Promise((r) => setTimeout(r, 5)); // distinct timestamps

  // ─────────────────────────────────────────────────────────────────────────
  // v0.1 constraint this setup works around: amounts are VISIBLE and the
  // chain binds each DECLARED input total (tx.inputAmountTotal) to the ONE
  // ring member sharing that amount (#tryApplyTxs in blockchain.js). So every
  // declared spend of amount A needs:
  //   (i)  A appearing EXACTLY ONCE among LIVE outputs (unambiguous binding),
  //   (ii) ≥ RING_SIZE-1 live outputs of amounts ≠ A (the mixin pool).
  // All early coinbases pay the identical base reward B (61 twins ⇒ (i) fails),
  // so we bootstrap with two legitimate mechanisms:
  //
  //  • Fee-collecting coinbases: a block carrying a real fee-f tx pays
  //    base+f — an amount seen nowhere else. The bootstrap block collects a
  //    1-pico fee, minting U1 = base+1, our first unique LIVE amount.
  //  • DECLARED single-input/single-output self-pays: the ladder starts from
  //    U1 = B+1 (unique by construction): rung i declares total Ui and emits
  //    Si = Ui − Fi exactly (strict balance equality — no burn exists; see
  //    verifyTxStructure), another globally unique amount, while REMOVING Ui
  //    from the live set. Its block collects fee Fi, paying out B+Fi — also
  //    unique. Geometric fees Fi = 2^(i−1)·M keep every value off every other.
  //
  // The bootstrap self-pay itself must stay UNDECLARED: its source is a
  // base-reward coinbase (60 live twins ⇒ declaration would fail binding).
  // A tx without inputAmountTotal skips binding/balance checks entirely
  // (until RingCT lands) — its key image still permanently marks the seed
  // output spent. Its mixin pool is the 60 remaining base-reward coinbases
  // (all ≠ B); its outputs B-1 (self) and 1 (fee) stay undeclared forever,
  // which also keeps them OUT of the ladder (B-1 regains twins as later
  // blocks pay it out via fees; declaring those would fail binding).
  //
  // Rings for declared spends are assembled deterministically from
  // amount-keyed pools (ringForDeclared): mixins come ONLY from live outputs
  // whose amount ∉ {A} ∪ LADDER — same-amount members break binding, and a
  // ladder twin elsewhere in the chain breaks it too (rule (i) scans the
  // whole UTXO set). Spent ladder values leave the live set, so they can
 // never be re-declared; the audit map `seen` proves distinctness up front.
  // For the undeclared bootstrap tx any mix is legal.
  // ─────────────────────────────────────────────────────────────────────────
  const B = baseReward(62n); // constant across this test's height range
  const fee = 1_000_000n; // pDNE per transfer (tx1/tx2)

  function pickBy(predFn, count, excludeHex) {
    const keys = [...chain.outputsByKey.keys()].filter(
      (k) => k !== excludeHex && predFn(BigInt(chain.outputsByKey.get(k).amount)),
    );
    if (keys.length < count) throw new Error(`not enough decoys (${keys.length}/${count})`);
    const picked = new Set();
    while (picked.size < count) picked.add(keys[Math.floor(Math.random() * keys.length)]);
    return [...picked];
  }

  /** Ring for a DECLARED spend of amount A: the real key is the ONLY member
   *  with amount A (chain binding requires candidates.length === 1), plus
   *  RING_SIZE-1 different-amount mixins. Spliced in at `realIdx`. */
  function ringForDeclared(realKeyHex, realKeyBytes, A, realIdx) {
    const others = pickBy((a) => a !== A, RING_SIZE - 1, realKeyHex);
    const ring = others.map(hexToBytes);
    ring.splice(realIdx, 0, realKeyBytes);
    return ring;
  }

  // Generic single-input, single-output DECLARED spend: srcOut (from wallet w)
  // → recipient `account`, paying `outAmount`, declaring total A = srcOut.amount.
  // The balance rule is strict equality (declared = outputs + fee ⇒ the chain
  // "burns" nothing; every pico lands in an output or the block's fee pool),
  // so outAmount must equal A − F exactly. Fully consensus-checked.
  function mkSpend(w, account, srcOut, outAmount, randR, declaredTotal, F = fee) {
    const A = srcOut.amount;
    const x = deriveOutputSecret(srcOut.txPublicKey, w.viewSecret, w.spendSecret);
    const ring = ringForDeclared(bytesToHex(srcOut.key), srcOut.key, A, 3);
    const prepared = prepareOutputs([{ amountPico: outAmount, address: account }], () => randR);
    const unsigned = buildTxPrefix({
      inputs: [{ ring }],
      outputs: prepared.map((p) => ({ amountPico: p.amountPico, key: p.key })),
      feePico: F,
      extra: assembleExtra(prepared),
    });
    const tx = signTx(unsigned, [{ realIndex: 3, x }]);
    if (declaredTotal !== undefined) tx.inputAmountTotal = declaredTotal;
    return tx;
  }

  // ── Phase 1: bootstrap maturity window (61 empty blocks, feesPico=0) ──
  let prev = chain.tip();
  for (let i = 0; i < COINBASE_MATURITY + 1; i++) {
    prev = mineNext(chain, miner, prev, 120, [], 0n, BigInt(i + 1));
    await sleep();
  }
  miner.scanChain(chain);

  // ── Phase 2: bootstrap self-pay (undeclared input-total escape hatch) ──
  // Spends one matured base-reward coinbase B, pays B-1 back to the miner and
  // routes 1 pico as the block's fee. Undeclared ⇒ no amount binding; its
  // mixin pool is the other 60 base-reward coinbases. The block carrying this
  // fee-1 tx pays base+1 as its coinbase (= U1, unique).
  //
  // It rides in a LATER block than the ladder's first spend: U1 is a coinbase
  // (maturity 60), so filler blocks must pass before rung 1 can declare-spend
  // it. mkSpend's ring builder needs ≥ RING_SIZE-1 live outputs of an amount
  // ≠ the declared one — that pool is the ~120 base-B coinbases plus every
  // fee-collecting coinbase and fresh self-output (all ≠ every ladder value),
  // which stays comfortably above 10 for the whole test.
  const mkSelfPay = (sourceOut, rScalar, declaredTotal) => {
    const x = deriveOutputSecret(sourceOut.txPublicKey, miner.viewSecret, miner.spendSecret);
    // Undeclared total ⇒ binding skipped ⇒ same-amount members would be legal,
    // but we still keep the ring honest by excluding the real key only.
    const decoys = pickBy(() => true, RING_SIZE - 1, sourceOut.keyHex);
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
    const tx = signTx(unsigned, [{ realIndex: realIdx, x }]);
    if (declaredTotal !== undefined) tx.inputAmountTotal = declaredTotal;
    return tx;
  };
  const seedOut = miner.availableOutputs(chain.height)[0];
  assert.ok(seedOut, 'need a matured coinbase to bootstrap');
  // Mark the seed output spent in OUR wallet up front: the chain cannot tell
  // us about it later (the self-pay declares no inputAmountTotal ⇒ no
  // image→output binding ⇒ the output lingers in our scan results), and
  // availableOutputs() would otherwise hand rung 1 a stale duplicate.
  {
    const xs = deriveOutputSecret(seedOut.txPublicKey, miner.viewSecret, miner.spendSecret);
    miner.spentImages.add(bytesToHex(keyImageForOutput(seedOut.key, xs)));
  }
  // The block must collect the tx's 1-pico fee so its coinbase pays B+1 —
  // otherwise it would pay plain base and collide with the other 60 live
  // base-reward coinbases, breaking rung 1's unique-amount binding.
  prev = mineNext(chain, miner, prev, 120, [mkSelfPay(seedOut, 5n)], 1n, 99n);
  await sleep();
  const u1Height = prev.header.height; // U1 coinbase unlocks at u1Height + 60

  // Filler blocks until U1 matures. Each pays plain base B — harmless twins
  // of the existing 60 (B is never a DECLARED amount in this test).
  while (chain.height < u1Height + COINBASE_MATURITY) {
    prev = mineNext(chain, miner, prev, 120, [], 0n, BigInt(500 + chain.height));
    await sleep();
  }
  miner.scanChain(chain);

  // ── Phase 3: unique-amount ladder via DECLARED fee-bearing self-pays ──
  // The declared-input pool starts EMPTY: every early output pays the base
  // reward B (twins ⇒ nothing is bindable). Each rung i therefore:
  //   • DECLARED-spends its source Ui (binding succeeds: exactly ONE live
  //     output carries that amount), paying itself Si = Ui − Fi — another
  //     globally unique amount — while REMOVING Ui from the live set;
  //   • rides in a block that collects the rung's fee Fi, so that block's
  //     coinbase pays B + Fi — yet another unique amount.
  // Rung sources chain through the self-outputs: U1 = B+1 (bootstrap block
  // fee), U2 = S1, …, U5 = S4. Fee schedule Fi = 2^(i−1)·M (M = DEFAULT_FEE):
  // geometric growth keeps Σ_{j<i} Fj < Fi, which makes every Si strictly
  // decreasing and pairwise distinct, and keeps every B+Fi off the ladder.
  // Only U1 is maturity-gated (coinbase); every Si is a regular tx output
  // (unlockTime 0) spendable in the very next block. After 5 rungs, S5 is
  // fresh, unique & live — and tx1 declared-spends it onto Alice.
  const M = 10_000_000n; // == DEFAULT_FEE: one fee unit
  const RUNGS = 5;
  const minerAccount = keysFromAddress(miner.getAddress());
  let curU = chain.blocks[u1Height].coinbase.outputs[0].amount; // U1 = B+1 (block height u1Height)
  assert.equal(curU, B + 1n);
  const seen = new Map(); // amount string -> description (distinctness audit)
  seen.set(curU.toString(), 'U1');
  for (let i = 1; i <= RUNGS; i++) {
    const F = (1n << BigInt(i - 1)) * M; // rung fee: 1M, 2M, 4M, 8M, 16M
    const s = curU - F;                  // strict balance: out = in − fee
    assert.ok(!seen.has(s.toString()), `rung ${i} self-output amount collides with ${seen.get(s.toString())}`);
    seen.set(s.toString(), `S${i}`);
    seen.set((B + F).toString(), `block-${i} coinbase (B+F${i})`);
    miner.scanChain(chain);
    const srcOut = miner.availableOutputs(chain.height).find((o) => o.amount === curU);
    assert.ok(srcOut, `ladder rung ${i}: need live output with amount ${curU}`);
    const tx = mkSpend(miner, minerAccount, srcOut, s, 100n + BigInt(i), curU, F);
    assert.ok(verifyTxStructure(tx).ok, `ladder tx ${i} invalid: ${verifyTxStructure(tx).reason}`);
    prev = mineNext(chain, miner, prev, 120, [tx], F, BigInt(200 + i));
    await sleep();
    curU = s; // chain through this rung's declared self-output
  }
  const uTop = curU; // S5, unique & live (minted by rung 5's self-output)

  // ── tx1: spend the ladder-top unique output S5 → alice ──
  // Declared total A = S5: exactly one live output carries it (the real
  // source), so ringForDeclared builds a ring whose ONLY S5 member is real —
  // the chain binds unambiguously. Staggered fee (2·M) makes payAlice
  // bit-disjoint from every Si and B+Fi, keeping it globally unique so tx2
  // can bind to it later.
  const src1 = (() => { miner.scanChain(chain); return miner.availableOutputs(chain.height).find((o) => o.amount === uTop); })();
  assert.ok(src1, 'ladder-top output must be available');
  const aliceAccount = keysFromAddress(alice.getAddress());
  const F1 = 2n * M; // staggered against all ladder values (see above)
  const payAlice = uTop - F1;
  assert.ok(!seen.has(payAlice.toString()), 'alice payment amount must stay globally unique');
  seen.set(payAlice.toString(), 'payAlice');
  const tx1 = mkSpend(miner, aliceAccount, src1, payAlice, 7n, uTop, F1);
  assert.ok(verifyTxStructure(tx1).ok, `tx1 invalid: ${verifyTxStructure(tx1).reason}`);
  assert.equal(tx1.inputs[0].ring.length, RING_SIZE);
  assert.equal(tx1.inputAmountTotal, uTop);
  prev = mineNext(chain, miner, prev, 120, [tx1], F1, 101n);
  await sleep();

  alice.scanChain(chain);
  assert.equal(alice.balancePico(), payAlice, 'alice received exactly the payment');

  // ── tx2: alice → bob (via the high-level wallet API) ──
  // Alice holds ONE output of globally-unique amount payAlice. Her wallet's
  // createTransaction declares inputAmountTotal = payAlice; the chain binds
  // it to her output because no other LIVE output shares that amount (all
  // ladder values were spent or differ; base-reward coinbases differ).
  // Single recipient of payAlice − fee ⇒ zero change ⇒ alice ends at 0.
  // Bob's amount is bit-disjoint from every ladder value (fee = 4·M).
  const bobAccount = keysFromAddress(bob.getAddress());
  const F2 = 4n * M;
  const payBob = payAlice - F2;
  assert.ok(!seen.has(payBob.toString()), 'bob payment amount must stay globally unique');
  seen.set(payBob.toString(), 'payBob');
  const tx2 = alice.createTransaction(
    chain,
    [{ address: bobAccount, amountPico: payBob }],
    { feePico: F2, forceInputWithAmount: payAlice },
  );
  assert.ok(verifyTxStructure(tx2).ok, `tx2 invalid: ${verifyTxStructure(tx2).reason}`);
  assert.equal(tx2.inputAmountTotal, payAlice);
  assert.equal(tx2.outputs.length, 1, 'exact spend ⇒ no change output');
  prev = mineNext(chain, miner, prev, 120, [tx2], F2, 102n);
  await sleep();

  bob.scanChain(chain);
  assert.equal(bob.balancePico(), payBob, 'bob received payment minus fee');
  assert.equal(alice.balancePico(), 0n, 'alice spent everything');

  // ── double spend: rebuild an equivalent tx from alice's now-spent output ──
  // Re-derive her original output & secret directly (simulating a malicious
  // replay). Its declared total payAlice now matches NO live output (hers was
  // consumed), but the key-image check fires FIRST in #tryApplyTxs.
  const spentOut = [...alice.outputs.values()][0];
  assert.equal(spentOut.amount, payAlice);
  const xd = deriveOutputSecret(spentOut.txPublicKey, alice.viewSecret, alice.spendSecret);
  const evilPrepared = prepareOutputs([{ amountPico: 1n, address: bobAccount }], () => 42n);
  const evilOthers = pickBy((a) => a !== payAlice, RING_SIZE - 1, spentOut.keyHex);
  const evilRing = evilOthers.map(hexToBytes);
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
  evil.inputAmountTotal = payAlice;
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
