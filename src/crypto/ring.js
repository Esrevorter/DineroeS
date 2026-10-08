/**
 * Ring signatures — LSAG (Linkable Spontaneous Anonymous Group) over Ed25519.
 * This is the exact signature family Monero uses to hide which input in a ring
 * is being spent, plus key images to prevent double-spending without linking
 * transactions to identities.
 *
 * Reference: Liu, Wei, Wong — "Linkable Spontaneous Anonymous Group Signature
 * for Ad Hoc Groups" (ACM CCS 2004). Monero implements this as "CLSAG/MLSAG";
 * we implement classic single-key LSAG with chained challenges (Monero's
 * serialization form): only c_0 and s_0..s_{n-1} are published.
 *
 * Scheme (message m, ring P_0..P_{n-1}, real index pi, secret x_pi):
 *   I = x_pi * Hp(P_pi)                              (key image)
 *   alpha <- random;  L_pi = alpha*G, R_pi = alpha*Hp(P_pi)
 *   walk ring forward from pi:
 *     c_{j+1} = Hs('C' || m || L_j || R_j || ring || I)
 *     for decoys: s_j <- random; L_j = s_j*G + c_j*P_j ; R_j = s_j*Hp(P_j) + c_j*I
 *   closure gives c_pi; set s_pi = alpha - c_pi*x_pi (mod l)
 *   publish sigma = (I, c_0, [s_0..s_{n-1}])
 *
 * Verify walks i=0..n-1 computing L_i,R_i from (c_i, s_i), derives c_{i+1},
 * and accepts iff after n steps c wraps back to c_0.
 */
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import {
  hashToScalar, hashToPoint, concatBytes, modN, subModN,
  bytesToScalarLE,
} from './hash.js';

ed.hashes.sha512 = sha512;
const G = ed.Point.BASE;

function randScalar() {
  return modN(bytesToScalarLE(ed.etc.randomBytes(32)));
}

/** Chained challenge: c_next = Hs('C' || m || L || R || ring || I). */
function chainChallenge(message, ringBytes, keyImage, Lbytes, Rbytes) {
  const parts = [Uint8Array.from([0x43 /* 'C' */]), message, Lbytes, Rbytes, ...ringBytes, keyImage];
  return hashToScalar(concatBytes(...parts));
}

/**
 * Sign a 32-byte message with an LSAG ring signature.
 * @param {Uint8Array} message - typically keccak256 of the tx prefix
 * @param {Uint8Array[]} ringPublicKeys - n compressed 32-byte points
 * @param {number} realIndex - position of the key we own
 * @param {bigint} x - matching private scalar
 * @returns {{keyImage: Uint8Array, c0: bigint, s: bigint[]}}
 */
export function signRing(message, ringPublicKeys, realIndex, x) {
  const n = ringPublicKeys.length;
  if (realIndex < 0 || realIndex >= n) throw new Error('bad realIndex');
  const ringPoints = ringPublicKeys.map((b) => ed.Point.fromBytes(b));
  const ringBytes = ringPublicKeys.map((b) => (b instanceof Uint8Array ? b : Uint8Array.from(b)));

  // Cross-check ownership: x*G must equal P_real (prevents signing wrong key)
  if (!G.multiply(modN(x)).equals(ringPoints[realIndex])) {
    throw new Error('secret key does not match the claimed ring member');
  }

  const HpReal = hashToPoint(ringBytes[realIndex]);
  const keyImagePoint = HpReal.multiply(modN(x));
  const keyImage = keyImagePoint.toBytes();
  const HpAll = ringBytes.map((b) => hashToPoint(b));

  const s = new Array(n).fill(0n);
  const c = new Array(n).fill(0n);

  // Start at the real index with the honest commitment.
  const alpha = randScalar();
  let Lbytes = G.multiply(alpha).toBytes();
  let Rbytes = HpReal.multiply(alpha).toBytes();

  // Walk the ring forward computing chained challenges and decoy responses.
  for (let step = 1; step <= n; step++) {
    const nextIdx = (realIndex + step) % n;
    const cNext = chainChallenge(message, ringBytes, keyImage, Lbytes, Rbytes);
    if (nextIdx === realIndex) {
      c[realIndex] = cNext; // loop closed
      break;
    }
    c[nextIdx] = cNext;
    s[nextIdx] = randScalar();
    const L = G.multiply(s[nextIdx]).add(ringPoints[nextIdx].multiply(cNext));
    const R = HpAll[nextIdx].multiply(s[nextIdx]).add(keyImagePoint.multiply(cNext));
    Lbytes = L.toBytes();
    Rbytes = R.toBytes();
  }

  // Real response closes the algebra: alpha = s_pi + c_pi*x  =>  s_pi = alpha - c_pi*x.
  s[realIndex] = subModN(alpha, modN(c[realIndex] * x));

  return { keyImage, c0: c[0], s };
}

/**
 * Verify an LSAG ring signature. Returns true/false (never throws on bad sigs).
 */
export function verifyRing(message, ringPublicKeys, signature) {
  const { keyImage, c0, s } = signature;
  const n = ringPublicKeys.length;
  if (!s || s.length !== n) return false;
  let ringPoints, ringBytes, I;
  try {
    ringPoints = ringPublicKeys.map((b) => ed.Point.fromBytes(b));
    ringBytes = ringPublicKeys.map((b) => (b instanceof Uint8Array ? b : Uint8Array.from(b)));
    I = ed.Point.fromBytes(keyImage);
  } catch {
    return false;
  }

  let c = modN(c0);
  for (let i = 0; i < n; i++) {
    try {
      const si = modN(BigInt(s[i]));
      const Pi = ringPoints[i];
      const Hpi = hashToPoint(ringBytes[i]);
      const Li = G.multiply(si).add(Pi.multiply(c));
      const Ri = Hpi.multiply(si).add(I.multiply(c));
      c = chainChallenge(message, ringBytes, Uint8Array.from(keyImage), Li.toBytes(), Ri.toBytes());
    } catch {
      return false;
    }
  }
  return c === modN(c0);
}

/** Key image for a one-time output: I = x*Hp(P). Nodes store these forever. */
export function keyImageForOutput(oneTimePublicKey, oneTimeSecret) {
  const P = oneTimePublicKey instanceof Uint8Array ? oneTimePublicKey : Uint8Array.from(oneTimePublicKey);
  const hp = hashToPoint(P);
  return hp.multiply(modN(BigInt(oneTimeSecret))).toBytes();
}

/** Serialize signature to JSON-friendly hex (wire format helper). */
export function ringSigToHex(sig) {
  return {
    keyImage: Buffer.from(sig.keyImage).toString('hex'),
    c0: BigInt(sig.c0).toString(16),
    s: sig.s.map((v) => BigInt(v).toString(16)),
  };
}

export function ringSigFromHex(obj) {
  return {
    keyImage: Uint8Array.from(Buffer.from(obj.keyImage, 'hex')),
    c0: BigInt('0x' + obj.c0),
    s: obj.s.map((h) => BigInt('0x' + h)),
  };
}
