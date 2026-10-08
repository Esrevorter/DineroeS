/**
 * DineroeS Merkle tree — mirrors Monero's tree-hash approach.
 *
 * Monero (and bytecoin lineage) hashes a binary tree where leaves are
 * keccak(tx_blob) and internal nodes are keccak(left || right). The root of
 * the transaction tree is the block's `pruned_hash`/`hash` field ("tree_hash"
 * in Monero code, src/cryptonote_basic/miner.cpp + "tree_supplemental").
 *
 * Odd-count nodes duplicate the last element at each level (same convention
 * as Bitcoin/Monero implementations), keeping the tree balanced-ish and the
 * root collision-resistant against subtree-substitution attacks.
 */
import { cnFastHash, concatBytes } from '../crypto/hash.js';

/** Hash a single leaf: keccak256(serialized tx blob). */
export function treeLeaf(blob) {
  return cnFastHash(blob);
}

/** Internal node hash: keccak256(left || right). */
export function treeBranch(left, right) {
  return cnFastHash(concatBytes(left, right));
}

/**
 * Compute the Merkle root over pre-hashed leaves.
 * @param {Uint8Array[]} leaves - 32-byte leaf hashes
 * @returns {Uint8Array} 32-byte root
 */
export function merkleRoot(leaves) {
  if (leaves.length === 0) return cnFastHash(new Uint8Array(0)); // empty-tree convention
  let level = [...leaves];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const l = level[i];
      const r = level[i + 1] ?? level[i]; // duplicate last on odd count
      next.push(treeBranch(l, r));
    }
    level = next;
  }
  return level[0];
}

/** Convenience: root directly over serialized blobs. */
export function merkleRootFromBlobs(blobs) {
  return merkleRoot(blobs.map(treeLeaf));
}

/**
 * Inclusion proof for leaf index i. Verifiers recompute with
 * verifyMerkleProof(leafHash, proof, index, root).
 */
export function merkleProof(leaves, index) {
  let level = [...leaves];
  const path = [];
  let idx = index;
  while (level.length > 1) {
    const siblingIdx = idx % 2 === 0 ? Math.min(idx + 1, level.length - 1) : idx - 1;
    path.push(level[siblingIdx]);
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const l = level[i];
      const r = level[i + 1] ?? level[i];
      next.push(treeBranch(l, r));
    }
    level = next;
    idx = Math.floor(idx / 2);
  }
  return path;
}

export function verifyMerkleProof(leafHash, proof, index, root) {
  let cur = leafHash;
  let idx = index;
  for (const sib of proof) {
    cur = idx % 2 === 0 ? treeBranch(cur, sib) : treeBranch(sib, cur);
    idx = Math.floor(idx / 2);
  }
  return Buffer.from(cur).equals(Buffer.from(root));
}
