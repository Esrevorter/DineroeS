/**
 * LWMA-1 difficulty adjustment — a faithful JS port of Monero's LWMA-1
 * algorithm (Zawy's "Monero: Difficulty Locking Weaknesses", reference
 * implementation in monero/src/cryptonote_basic/difficulty.cpp).
 *
 * Canonical formula (weighted linear, newest block weighs most):
 *   D_next = TARGET · Σ_{i=1..N} ( i · d_i ) / Σ_{i=1..N} ( i · dt_i )
 * where d_i is the PER-BLOCK difficulty of the i-th block in the window and
 * dt_i its solve time. Sanity: for constant d and constant dt this reduces
 * exactly to D = d·TARGET/dt — blocks twice as fast ⇒ difficulty ×2.
 *
 * Parameters identical to Monero defaults:
 *   - window N = 60 blocks (DIFFICULTY_LWMA_WINDOW)
 *   - target T = 120 s (TARGET_BLOCK_TIME)
 * Guards (same spirit as Monero):
 *   - each dt clamped to [0, 7·T] (time-warp protection)
 *   - result floored at 1 and capped at the window's total cumulative work
 */
import { TARGET_BLOCK_TIME, DIFFICULTY_LWMA_WINDOW } from '../constants.js';

/**
 * @param {Array<{timestamp:number, difficulty:bigint}>} prevBlocks
 *        Most-recent-last slice of the chain, length up to N (we take last N).
 *        Each entry carries the block's timestamp (unix seconds) and its
 *        PER-BLOCK difficulty as bigint. If an entry carries
 *        `cumulativeDifficulty` instead, we derive per-block diffs from it.
 * @param {number} height height of the new block being solved for
 * @param {{target?: number, window?: number}} opts test overrides
 * @returns {bigint} next difficulty (>= 1)
 */
export function nextDifficultyLWMA(prevBlocks, height, opts = {}) {
  const TARGET = BigInt(opts.target ?? TARGET_BLOCK_TIME);
  const WINDOW = opts.window ?? DIFFICULTY_LWMA_WINDOW;

  if (height === 0) return 1n; // genesis handled elsewhere
  const blocks = prevBlocks.slice(-WINDOW);
  const N = blocks.length;
  if (N === 0) return 1n;

  // Normalize entries to per-block difficulties. Entries may carry either a
  // plain per-block `difficulty`, or `cumulativeDifficulty` (in which case we
  // difference consecutive cumulatives — the Monero node's getCumdiff approach).
  const hasCum = blocks.some((b) => b.cumulativeDifficulty !== undefined);
  let diffs;
  if (hasCum) {
    diffs = blocks.map((b, i) => {
      const cd = BigInt(b.cumulativeDifficulty);
      const prevCd = i > 0 ? BigInt(blocks[i - 1].cumulativeDifficulty) : 0n;
      return cd - prevCd > 0n ? cd - prevCd : 1n;
    });
  } else {
    diffs = blocks.map((b) => BigInt(b.difficulty));
  }

  let sumWeightedTime = 0n;   // Σ i·dt_i
  let sumWeightedDiff = 0n;   // Σ i·d_i
  const maxBlockTime = TARGET * 7n;

  for (let idx = 0; idx < N; idx++) {
    const weight = BigInt(idx + 1); // 1..N, newest gets largest weight
    const tsPrev = idx > 0
      ? BigInt(blocks[idx - 1].timestamp)
      : BigInt(blocks[idx].timestamp) - TARGET; // synthetic dt=T before window
    let dt = BigInt(blocks[idx].timestamp) - tsPrev;
    if (dt > maxBlockTime) dt = maxBlockTime;
    if (dt < 0n) dt = 0n;
    sumWeightedTime += dt * weight;
    sumWeightedDiff += diffs[idx] * weight;
  }

  // ── LWMA-1 (Zawy canonical, monero/src/cryptonote_basic/difficulty.cpp) ──
  //   D_next = T · Σ_{i=1..N} ( i · d_i ) / Σ_{i=1..N} ( i · dt_i )
  // For constant d and dt this reduces EXACTLY to d·T/dt: blocks arriving at
  // target pace keep difficulty unchanged; twice as fast ⇒ ×2, etc.
  const denom = sumWeightedTime > 0n ? sumWeightedTime : 1n;
  let nextDiff = (TARGET * sumWeightedDiff) / denom;

  // Sanity bounds (Monero's guards): never below 1, never above the parent
  // chain's total cumulative work (a block can't be harder than everything
  // before it combined).
  if (nextDiff < 1n) nextDiff = 1n;
  let cumTotal = 0n;
  for (const d of diffs) cumTotal += d;
  if (cumTotal > 0n && nextDiff > cumTotal) nextDiff = cumTotal;

  return nextDiff;
}
