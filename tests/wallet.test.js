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
  const alice = new Wallet(randomSeed());
  const bob = new Wallet(randomSeed());
  const sleep = () => new Promise((r) => setTimeout(r, 5)); // distinct timestamps

  // ─────────────────────────────────────────────────────────────────────────
  // v0.1 constraint this setup works around: amounts are VISIBLE and the
  // chain binds each DECLARED input total (tx.inputAmountTotal) to the ONE
  // ring member sharing that amount (#tryApplyTxs in blockchain.js). So a
  // declared-input spend needs its source amount A to appear EXACTLY ONCE
  // among live outputs — which means the ring needs a same-amount DECOY too,
  // i.e. A must appear ≥2× live while only ONE instance may end up in any
  // ring. All early coinbases pay the identical base reward, so we bootstrap
  // the required state with two legitimate mechanisms:
  //
  //  • UNDECLARED escape hatch: a tx with no inputAmountTotal skips binding/
  //    balance checks entirely (until RingCT lands). One bootstrap self-pay
  //    uses it — its key image still permanently marks the seed output spent.
  //  • Fee-collecting coinbases: a block carrying a real fee-F tx pays
  //    base+F — an amount seen nowhere else. Chaining such txs yields a
  //    ladder of DISTINCT unique coinbase amounts U1 < U2 < ... < Uk, each
  //    rung's own self-output paying a burn-shifted value Si ≠ anything else.
  //    Crucially, spending Ui leaves Ui OUT of the live set, so when tx1
  //    spends Uk (the fresh top rung) the pool of same-amount decoys for
  //    earlier rungs stays intact while Uk itself has NO twin — exactly what
  //    the "bind to the ONE member" rule requires… except the ring must then
  //    contain ZERO other members of amount Uk, which holds trivially since
  //    Uk was just minted. ✓
  //
  // Rings are assembled deterministically from amount-keyed pools:
  //   ringFor(realKey, A) = [live outputs of amount A ≠ real]  (may be empty)
  //                       + [live outputs of amounts ≠ A, to fill RING_SIZE-1]
  // For declared spends of amount A the chain demands EXACTLY ONE member of
  // amount A in the ring (the real one), so sameAmt must be EMPTY and mixins
  // must all differ from A. For undeclared bootstrap txs any mix is legal.
  // ─────────────────────────────────────────────────────────────────────────
  const fee = 1_000_000n; // pDNE per transfer

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
  // → recipient `account`, paying `outAmount`, declaring total A = srcOut.amount,
  // burning the remainder (A - outAmount - fee ≥ 0). Fully consensus-checked.
  function mkSpend(w, account, srcOut, outAmount, randR) {
    const A = srcOut.amount;
    const x = deriveOutputSecret(srcOut.txPublicKey, w.viewSecret, w.spendSecret);
    const ring = ringForDeclared(srcOut.keyHex, srcOut.key, A, 3);
    const prepared = prepareOutputs([{ amountPico: outAmount, address: account }], () => randR);
    const unsigned = buildTxPrefix({
      inputs: [{ ring }],
      outputs: prepared.map((p) => ({ amountPico: p.amountPico, key: p.key })),
      feePico: fee,
      extra: assembleExtra(prepared),
    });
    const tx = signTx(unsigned, [{ realIndex: 3, x }]);
    tx.inputAmountTotal = A;
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
  // Spends one matured base-reward coinbase, burns 1 pico, pays base-1 back
  // to the miner. Its BLOCK's coinbase pays base+1 (= U1, unique).
  const mkSelfPay = (sourceOut, rScalar) => {
    const x = deriveOutputSecret(sourceOut.txPublicKey, miner.viewSecret, miner.spendSecret);
    // Undeclared total ⇒ binding skipped ⇒ same-amount members are legal here.
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
    return signTx(unsigned, [{ realIndex: realIdx, x }]); // deliberately no inputAmountTotal
  };
  const seedOut = miner.availableOutputs(chain.height)[0];
  assert.ok(seedOut, 'need a matured coinbase to bootstrap');
  prev = mineNext(chain, miner, prev, 120, [mkSelfPay(seedOut, 5n)], 0n, 99n);
  await sleep();

  // ── Phase 3: unique-amount ladder via REAL declared fee-bearing self-pays ──
  // Rung i spends Ui (declared ⇒ fully checked; valid because Ui appears
  // exactly once live and its ring contains no other Ui-valued member),
  // collects fee F into the next coinbase (U(i+1) = base + F·i + 1) and pays
  // the miner Si = Ui - F - burn_i (burn_i = 1000·i keeps every Si distinct
  // from every Uj and Sk). After 4 rungs, U5 = base + 4F + 1 is freshly
  // minted, unique, and immediately spendable (non-coinbase unlockTime = 0).
  const minerAccount = keysFromAddress(miner.getAddress());
  let curU = prev.coinbase.outputs[0].amount; // U1 = base + 1
  const seen = new Map(); // amount string -> description (distinctness audit)
  seen.set(curU.toString(), 'U1');
  for (let i = 1; i <= 4; i++) {
    miner.scanChain(chain);
    const srcOut = miner.availableOutputs(chain.height).find((o) => o.amount === curU);
    assert.ok(srcOut, `ladder rung ${i}: need live output with amount ${curU}`);
    const burn = 1000n * BigInt(i);
    const s = curU - fee - burn;
    assert.ok(!seen.has(s.toString()), `rung ${i} self-output amount collides with ${seen.get(s.toString())}`);
    seen.set(s.toString(), `S${i}`);
    const tx = mkSpend(miner, minerAccount, srcOut, s, 100n + BigInt(i));
    assert.ok(verifyTxStructure(tx).ok, `ladder tx ${i} invalid: ${verifyTxStructure(tx).reason}`);
    prev = mineNext(chain, miner, prev, 120, [tx], fee, BigInt(200 + i));
    await sleep();
    curU = prev.coinbase.outputs[0].amount; // U(i+1) = base + F·i + 1
    assert.ok(!seen.has(curU.toString()), `rung ${i + 1} coinbase amount collides`);
    seen.set(curU.toString(), `U${i + 1}`);
  }
  miner.scanChain(chain);
  const uTop = curU; // U5, unique & live (just minted by rung 4's block)

  // ── tx1: spend the ladder-top unique coinbase U5 → alice ──
  // Declared total A = U5: exactly one live output carries it (the real
  // source), so ringForDeclared builds a ring whose ONLY U5 member is real —
  // the chain binds unambiguously. Pays alice U5 - fee - burn1 (burn keeps
  // alice's amount distinct from every ladder value → tx2 can bind later).
  const src1 = miner.availableOutputs(chain.height).find((o) => o.amount === uTop);
  assert.ok(src1, 'ladder-top coinbase must be available');
  const aliceAccount = keysFromAddress(alice.getAddress());
  const burn1 = 5000n;
  const payAlice = uTop - fee - burn1;
  assert.ok(!seen.has(payAlice.toString()), 'alice payment amount must stay globally unique');
  seen.set(payAlice.toString(), 'payAlice');
  const tx1 = mkSpend(miner, aliceAccount, src1, payAlice, 7n);
  assert.ok(verifyTxStructure(tx1).ok, `tx1 invalid: ${verifyTxStructure(tx1).reason}`);
  assert.equal(tx1.inputs[0].ring.length, RING_SIZE);
  assert.equal(tx1.inputAmountTotal, uTop);
  prev = mineNext(chain, miner, prev, 120, [tx1], fee, 101n);
  await sleep();

  alice.scanChain(chain);
  assert.equal(alice.balancePico(), payAlice, 'alice received exactly the payment');

  // ── tx2: alice → bob (via the high-level wallet API) ──
  // Alice holds ONE output of globally-unique amount payAlice. Her wallet's
  // createTransaction declares inputAmountTotal = payAlice; the chain binds
  // it to her output because no other LIVE output shares that amount (all
  // ladder values were spent or differ; base-reward coinbases differ).
  // Bob receives payAlice - fee - burn2 (no change output → exact balance).
  const bobAccount = keysFromAddress(bob.getAddress());
  const burn2 = 3000n;
  const payBob = payAlice - fee - burn2;
  // Temporarily declare the burn via an explicit second output to ourselves?
  // No — keep it simple: two recipients (bob + miner-burn is impossible), so
  // instead split: bob gets payBob, and alice pays the rest as change to
  // herself… but then her balance ≠ 0 after spending. Cleanest: single output
  // to bob of payAlice - fee, zero burn, exact spend. Binding still fine:
  // payAlice unique live. Do that.
  const payBobFinal = payAlice - fee;
  const tx2 = alice.createTransaction(chain, [{ address: bobAccount, amountPico: payBobFinal }], { feePico: fee });
  assert.ok(verifyTxStructure(tx2).ok, `tx2 invalid: ${verifyTxStructure(tx2).reason}`);
  assert.equal(tx2.inputAmountTotal, payAlice);
  prev = mineNext(chain, miner, prev, 120, [tx2], fee, 102n);
  await sleep();

  bob.scanChain(chain);
  assert.equal(bob.balancePico(), payBobFinal, 'bob received payment minus fee');
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
