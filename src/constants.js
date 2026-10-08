/**
 * DineroeS protocol constants.
 *
 * Every value here is a consensus parameter: changing it changes the network.
 * Names mirror Monero's monero-project/monero/src/cryptonote_config.h where possible.
 */

// ── Currency ────────────────────────────────────────────────────────────────
export const COIN_NAME = 'DineroeS';
export const CURRENCY_TICKER = 'DNE';
/** 1 DNE = 10^12 pDNE (picoDineroeS), mirroring Monero's piconero. */
export const COIN_DECIMALS = 12;
export const COIN = 10n ** BigInt(COIN_DECIMALS); // 1_000_000_000_000
export const MAX_MONEY = 10_000_000n * COIN; // hard cap narrative; emission stops before this

// ── Address prefixes (like Monero's 18/19/36 network byte) ─────────────────
export const NET_MAINNET = 1;
export const NET_TESTNET = 2;
export const NET_STAGENET = 19;
export const ADDRESS_PREFIX_STANDARD = 0x18 + NET_MAINNET - 1; // 0x18 mainnet standard address
export const ADDRESS_PREFIX_SUBADDRESS = 0x28;
export const ADDRESS_PREFIX_INTEGRATED = 0x4a;

// ── Privacy parameters (Monero defaults mirrored) ───────────────────────────
/** Ring size (number of decoys incl. the real input). Monero default: 11. */
export const RING_SIZE = 11;
/** Minimum confirmations before outputs are spendable (Monero: 10). */
export const MINIMUM_CONFIRMATIONS = 10;
/** Default unlock time for outgoing transactions. */
export const DEFAULT_UNLOCK_TIME = 0;

// ── Blocks ──────────────────────────────────────────────────────────────────
/** Target block time in seconds (Monero: 120). */
export const TARGET_BLOCK_TIME = 120;
/** LWMA difficulty adjustment window length (Monero: 60). */
export const DIFFICULTY_LWMA_WINDOW = 60;
/** Block size limits: median-based dynamic limit (Monero-style). */
export const BLOCK_SIZE_MAX = 1_000_000; // absolute cap, bytes

// ── Emission curve (Monero's formula, retuned for DineroeS) ────────────────
/**
 * Monero:      base_reward(h) = M >> (h / C), decay per "halving" of C blocks.
 *              Monero uses C = 1200 blocks (~4h halving-ish decay).
 * DineroeS keeps the exact same shape but a much slower decay so the base
 * reward is meaningful at 120 s blocks and does not collapse to zero instantly:
 *   C = EMISSION_SPEED_FACTOR = 20_000 blocks ≈ 27.8 days per halving.
 * With M = 100 DNE:
 *   - first halving at height 20_000 (100 → 50 DNE)
 *   - after 8 halvings (height 160_000) base = 0.39 DNE < tail ⇒ tail takes
 *     over permanently from block 160_001
 *   - pre-tail supply ≈ 3.98M DNE; then +0.6 DNE/block forever
 *     (~2.1M DNE/year tail inflation — deliberately generous tail, like
 *     Monero's permanent 0.6 XMR/block, scaled to our faster blocks)
 */
export const EMISSION_SPEED_FACTOR = 20_000;
/** Initial base-reward amplitude M, in pDNE (100 DNE at block 1). */
export const EMISSION_M_PICO = 100_000000000000n; // 100 * 10^12
/** Permanent tail emission (Monero analog: 0.6 XMR/block; ours: 0.6 DNE/block). */
export const TAIL_EMISSION_PER_BLOCK = 600_000000000n; // 0.6 DNE per block
/** Block maturity: coinbase output must mature before spending (Monero: 60). */
export const COINBASE_MATURITY = 60;

// ── Fees ────────────────────────────────────────────────────────────────────
/** Absolute minimum fee per kB-ish unit (Monero: 10000 pXMR/kB analog). */
export const FEE_PER_KB = 10_000n; // picoDNE
export const FEE_QUANTIZATION_STEP = 1_000_000n; // like Monero's quantization mask
export const DEFAULT_FEE = 10_000_000n; // 0.00001 DNE floor

// ── Crypto domain parameters ────────────────────────────────────────────────
/** Ed25519 group order ℓ. Scalars live in Z/ℓZ, exactly as in Monero. */
export const ED25519_SCALAR_ORDER =
  0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;
/** Domain separator prefix for hash-to-scalar ("S" in Monero's H_s). */
export const HASH_TO_SCALAR_PREFIX = 0x53;
/** Key image derivation uses "H_p(P)" with this domain prefix. */
export const HASH_TO_POINT_PREFIX = 0x48;

// ── Network / P2P ───────────────────────────────────────────────────────────
export const P2P_PORT_MAINNET = 19080;
export const P2P_PORT_TESTNET = 19081;
export const RPC_PORT_MAINNET = 18081;
export const RPC_PORT_TESTNET = 28081;
export const PROTOCOL_VERSION = 1;
export const MAX_PEER_MESSAGE_BYTES = 2 * 1024 * 1024;
export const MEMPOOL_EXPIRY_SECONDS = 3 * 24 * 3600; // Monero-like tx liveness

// ── Genesis block (DineroeS-specific) ───────────────────────────────────────
export const GENESIS_TIMESTAMP = 1750000000; // 2025-06-15T16:13:20Z — DineroeS launch
export const GENESIS_DIFFICULTY = 1000n;
export const GENESIS_COINBASE_TX_EXTRA_MESSAGE =
  'DineroeS: dinero para todos — privacy is not a crime';
export const GENESIS_NONCE = 0;
export const GENESIS_REWARD = 0n; // genesis pays nothing

// ── Mnemonic (wallet seed) ──────────────────────────────────────────────────
/** Number of words in a DineroeS 256-bit seed mnemonic (Monroseed-25 analog). */
export const MNEMONIC_WORDS = 25;
