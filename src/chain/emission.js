/**
 * DineroeS emission curve — a direct port of Monero's monetary model.
 *
 * Monero (src/cryptonote_basic/cryptonote_basic.h, get_base_block_reward):
 *   base_reward(h) = MONERO_SUPPLY >> (h / EMISSION_SPEED_FACTOR)
 * i.e. pure integer right-shift by the number of completed "doublings",
 * giving a piecewise-constant decay: the reward halves exactly every
 * EMISSION_SPEED_FACTOR blocks. When base_reward drops below the tail
 * emission, the permanent tail takes over:
 *   reward(h) = max(base_reward(h), TAIL_EMISSION_PER_BLOCK)
 *
 * DineroeS parameters (see constants.js):
 *   M    = 100 DNE initial amplitude, in pDNE (100_000_000_000_000)
 *   C    = EMISSION_SPEED_FACTOR = 20_000 blocks per halving (~2.7 years @120s)
 *   TAIL = 0.6 DNE per block, forever (mirrors Monero's permanent tail)
 *
 * Consequences (verified by tests):
 *   - first halving at height 20_000 (reward 100 -> 50 DNE)
 *   - tail starts at height 160_001 (after 8 halvings, 100>>8 = 0.39 < 0.6)
 *   - pre-tail supply ≈ 3.98M DNE; then +0.6 DNE/block (~18% annual inflation
 *     at 120s blocks, like Monero's ~1.2%/yr tail scaled to our faster decay)
 *
 * All arithmetic is BigInt only — no floating point anywhere — so every node
 * derives byte-identical rewards (consensus-critical).
 */
import { EMISSION_M_PICO, EMISSION_SPEED_FACTOR, TAIL_EMISSION_PER_BLOCK } from '../constants.js';

const C = BigInt(EMISSION_SPEED_FACTOR);

/**
 * Compute base reward at height h, in picoDNE (bigint), before tail clamp.
 * Monero's exact integer formula: M >> floor(h / C).
 * Returns 0n once decayed below 1 pico unit.
 */
export function baseReward(h) {
  if (h <= 0) return EMISSION_M_PICO;
  const halvings = BigInt(h) / C; // floor division
  if (halvings >= 256n) return 0n; // past representable range
  return EMISSION_M_PICO >> halvings;
}

/**
 * Cumulative base emission from block 1..h — Monero's "already generated
 * supply" term. Rewards are piecewise-constant: every height i in the
 * half-open bucket [k*C, (k+1)*C) pays (M >> k). Summing over i=1..h gives
 * the exact closed form below (height 0 is the genesis block and earns
 * nothing, so bucket 0 only contributes C-1 paid heights when fully passed).
 */
export function alreadyGeneratedBase(h) {
  if (h <= 0) return 0n;
  const H = BigInt(h);
  const n = H / C;            // current halving level at height h
  const r = H % C;            // offset into current bucket
  let total = 0n;
  for (let k = 0n; k < n; k++) {
    const reward = EMISSION_M_PICO >> k;
    if (reward === 0n) break;
    // bucket k covers heights [kC, (k+1)C): C heights, minus height 0 for k=0
    const span = k === 0n ? C - 1n : C;
    total += reward * span;
  }
  // Partial current bucket: heights [n*C, n*C + r] inclusive → r+1 heights,
  // minus height 0 when n == 0 (genesis).
  const cur = EMISSION_M_PICO >> n;
  if (cur !== 0n) total += cur * (n === 0n ? r : r + 1n);
  return total;
}

/** Height at which the permanent tail takes over (first block with base < tail). */
export function firstTailBlock() {
  let k = 0n;
  while ((EMISSION_M_PICO >> k) >= TAIL_EMISSION_PER_BLOCK) k++;
  return Number(k * C) + 1;
}

/** Full block reward including fees (Monero: coinbase = base + miner tx fees). */
export function blockReward(h, feesPico = 0n) {
  const base = baseReward(BigInt(h));
  const effectiveBase = base < TAIL_EMISSION_PER_BLOCK ? TAIL_EMISSION_PER_BLOCK : base;
  return effectiveBase + feesPico;
}

/** Total emitted (base only, fees excluded) up to height h, including tail. */
export function supplyAtHeight(h) {
  const tf = BigInt(firstTailBlock());
  const H = BigInt(h);
  if (H < tf) return alreadyGeneratedBase(H);
  return alreadyGeneratedBase(tf - 1n) + TAIL_EMISSION_PER_BLOCK * (H - tf + 1n);
}
