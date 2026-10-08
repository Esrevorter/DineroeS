import { Wallet } from './src/wallet/wallet.js';
import { Blockchain } from './src/chain/blockchain.js';
import { assembleBlock, mineBlock } from './src/chain/block.js';
import { randomSeed, keysFromAddress, deriveOutputSecret } from './src/crypto/keys.js';
import { hexToBytes } from './src/crypto/hash.js';
import { prepareOutputs, buildTxPrefix, assembleExtra, signTx } from './src/chain/transaction.js';
import { COINBASE_MATURITY, RING_SIZE } from './src/constants.js';

function mineNext(chain, minerWallet, prev, txs = [], feesPico = 0n, rSeed = 7n) {
  const solved = mineBlock(assembleBlock({
    timestamp: prev.header.timestamp + 120,
    prevId: hexToBytes(prev.id),
    height: prev.header.height + 1,
    difficulty: 1n,
    cumulativeDifficulty: BigInt(prev.header.cumulativeDifficulty) + 1n,
    nonce: 0,
    minerAddress: { account: { spendPublic: minerWallet.spendPublic }, viewPublic: minerWallet.viewPublic },
    rSeed, txs, feesPico,
  }), 200_000);
  if (!solved) throw new Error('mining failed');
  const res = chain.addBlock(solved, { skipDifficultyCheck: true });
  if (!res.ok) throw new Error('addBlock failed: ' + res.reason);
  return solved;
}

const chain = new Blockchain();
chain.initGenesis();
const miner = new Wallet(randomSeed());
let prev = chain.tip();
for (let i = 0; i < COINBASE_MATURITY + 1; i++) prev = mineNext(chain, miner, prev, [], 0n, BigInt(i + 1));
console.log('after phase1 live outputs:', chain.outputsByKey.size);

miner.scanChain(chain);
const seedOut = miner.availableOutputs(chain.height)[0];
const x = deriveOutputSecret(seedOut.txPublicKey, miner.viewSecret, miner.spendSecret);
const allKeys = [...chain.outputsByKey.keys()].filter((k) => k !== seedOut.keyHex);
console.log('seedOut.amount =', seedOut.amount, 'pool size for pickBy(any):', allKeys.length);
const decoys = [];
while (decoys.length < RING_SIZE - 1) { const k = allKeys[Math.floor(Math.random() * allKeys.length)]; if (!decoys.includes(k)) decoys.push(k); }
const ring = decoys.map(hexToBytes); ring.splice(2, 0, seedOut.key);
const minerAccount = keysFromAddress(miner.getAddress());
const prepared = prepareOutputs([{ amountPico: seedOut.amount - 1n, address: minerAccount }], () => 5n);
const unsigned = buildTxPrefix({ inputs: [{ ring }], outputs: prepared.map((p) => ({ amountPico: p.amountPico, key: p.key })), feePico: 1n, extra: assembleExtra(prepared) });
const selfPay = signTx(unsigned, [{ realIndex: 2, x }]);
prev = mineNext(chain, miner, prev, [selfPay], 0n, 99n);
console.log('after phase2 live outputs:', chain.outputsByKey.size);

const fee = 1_000_000n;
let curU = prev.coinbase.outputs[0].amount;
for (let i = 1; i <= 4; i++) {
  miner.scanChain(chain);
  const srcOut = miner.availableOutputs(chain.height).find((o) => o.amount === curU);
  if (!srcOut) { console.log('MISSING rung source at i=', i, 'curU=', curU); break; }
  const burn = 1000n * BigInt(i);
  const s = curU - fee - burn;
  const xx = deriveOutputSecret(srcOut.txPublicKey, miner.viewSecret, miner.spendSecret);
  const others = [...chain.outputsByKey.keys()].filter((k) => k !== srcOut.keyHex && BigInt(chain.outputsByKey.get(k).amount) !== curU);
  console.log(`rung ${i}: pool != U(${curU}) size =`, others.length);
  const picked = new Set(); while (picked.size < RING_SIZE - 1) picked.add(others[Math.floor(Math.random() * others.length)]);
  const rg = [...picked].map(hexToBytes); rg.splice(3, 0, srcOut.key);
  const pr = prepareOutputs([{ amountPico: s, address: minerAccount }], () => 100n + BigInt(i));
  const un = buildTxPrefix({ inputs: [{ ring: rg }], outputs: pr.map((p) => ({ amountPico: p.amountPico, key: p.key })), feePico: fee, extra: assembleExtra(pr) });
  const tx = signTx(un, [{ realIndex: 3, x: xx }]); tx.inputAmountTotal = curU;
  prev = mineNext(chain, miner, prev, [tx], fee, BigInt(200 + i));
  curU = prev.coinbase.outputs[0].amount;
  console.log(`rung ${i} OK; live outputs:`, chain.outputsByKey.size, 'next U:', curU);
}
miner.scanChain(chain);
const src1 = miner.availableOutputs(chain.height).find((o) => o.amount === curU);
console.log('uTop found?', !!src1, 'uTop =', curU);
const payAlice = curU - fee - 5000n;
const poolNotPayAlice = [...chain.outputsByKey.keys()].length; // after tx1 not yet applied
console.log('final pool size (a !== payAlice filter runs over this):', poolNotPayAlice);
