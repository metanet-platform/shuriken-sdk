/**
 * shuriken-sdk — Groth16 verification over @noble/curves bn254.
 *
 * WHAT: `verifyGroth16(vkey, publicSignals, proof)` — the pairing check for a
 *       snarkjs-format Groth16 proof on BN254 (circom's `bn128`), implemented
 *       directly on `@noble/curves`' bn254 pairing so the SDK does NOT need
 *       snarkjs at runtime. snarkjs would drag in ffjavascript + wasm workers
 *       (~MBs and a worker-spawning surface); @noble/curves is already inlined
 *       for signature verification, so this verifier costs ~0 extra deps.
 * WHY it is sound to swap: Groth16 verification is a fixed algebraic check —
 *       with vk_x = IC[0] + s·IC[1] (nPublic = 1 here, s = leafHash):
 *
 *           e(A, B) == e(alpha₁, beta₂) · e(vk_x, gamma₂) · e(C, delta₂)
 *
 *       equivalently  e(−A, B) · e(alpha₁, beta₂) · e(vk_x, gamma₂) · e(C, delta₂) == 1
 *       in Fp12 — which is exactly what we compute with one batched
 *       Miller loop + final exponentiation (`pairingBatch`).
 *
 * COORDINATE CONVENTIONS (the part that silently breaks if you guess):
 *   • snarkjs serializes every coordinate as a DECIMAL string.
 *   • G1 points are projective triples `[x, y, '1']` — affine with an explicit
 *     z=1 limb (`['0','1','0']` is the point at infinity; we reject it: no
 *     honest vkey/proof element is ever infinity here).
 *   • G2/Fp2 elements are `[x0, x1]` meaning x0 + x1·u — i.e. snarkjs's
 *     `[x0, x1]` maps to noble's `{ c0: x0, c1: x1 }` IN THAT ORDER (c0 is the
 *     "real" limb). Getting this backwards makes every proof fail on-curve
 *     validation or the pairing.
 *   • G2 points are `[[x0,x1],[y0,y1],['1','0']]` — affine with z = 1 + 0·u.
 *
 * Every parse/validation failure returns `false` (never a raw throw): to a
 * caller, "malformed proof" and "wrong proof" are the same answer — invalid.
 */

import { bn254 } from '@noble/curves/bn254';
import type { Groth16Proof } from '../types';
import type { Groth16Vkey } from './vkeys';

/** BN254 scalar-field order r — public signals must be canonical (< r), like snarkjs enforces. */
const SCALAR_FIELD_ORDER =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Parse a snarkjs decimal-string coordinate into a bigint (strict: digits only). */
function parseDec(s: unknown): bigint {
  if (typeof s !== 'string' || !/^[0-9]+$/.test(s)) throw new Error('non-decimal coordinate');
  return BigInt(s);
}

/** noble's G1/G2 point types, inferred so this file tracks the library exactly. */
type G1 = ReturnType<typeof bn254.G1.Point.fromAffine>;
type G2 = ReturnType<typeof bn254.G2.Point.fromAffine>;

/**
 * Parse a snarkjs G1 triple `[x, y, '1']` into a validated noble G1 point.
 * Rejects non-affine encodings (z ≠ 1): snarkjs always emits z=1 for real
 * points, and accepting arbitrary z would let a forger smuggle the point at
 * infinity past the on-curve check.
 */
function parseG1(coords: unknown): G1 {
  if (!Array.isArray(coords) || coords.length !== 3) throw new Error('G1 point must have 3 limbs');
  if (parseDec(coords[2]) !== 1n) throw new Error('G1 point must be affine (z = 1)');
  const point = bn254.G1.Point.fromAffine({ x: parseDec(coords[0]), y: parseDec(coords[1]) });
  point.assertValidity(); // on-curve + subgroup (G1 cofactor is 1 on bn254, but keep the invariant explicit)
  return point;
}

/**
 * Parse a snarkjs G2 triple `[[x0,x1],[y0,y1],['1','0']]` into a validated
 * noble G2 point. snarkjs `[c0, c1]` order maps 1:1 onto noble `{c0, c1}`
 * (x0 + x1·u — see the module WHY note). `assertValidity` enforces on-curve
 * AND subgroup membership — essential on G2, where the cofactor is huge and
 * a non-subgroup point would corrupt the pairing.
 */
function parseG2(coords: unknown): G2 {
  if (!Array.isArray(coords) || coords.length !== 3) throw new Error('G2 point must have 3 limbs');
  const limb = (pair: unknown): { c0: bigint; c1: bigint } => {
    if (!Array.isArray(pair) || pair.length !== 2) throw new Error('G2 limb must be an Fp2 pair');
    return { c0: parseDec(pair[0]), c1: parseDec(pair[1]) };
  };
  const z = limb(coords[2]);
  if (z.c0 !== 1n || z.c1 !== 0n) throw new Error('G2 point must be affine (z = 1 + 0u)');
  const point = bn254.G2.Point.fromAffine({ x: limb(coords[0]), y: limb(coords[1]) });
  point.assertValidity();
  return point;
}

/**
 * Verify a Groth16 proof against a verification key and its public signals.
 *
 * WHAT: parses the snarkjs-format vkey + proof into noble bn254 points,
 *       computes vk_x = IC[0] + Σ sᵢ·IC[i+1], and checks
 *       e(−A,B) · e(alpha₁,beta₂) · e(vk_x,gamma₂) · e(C,delta₂) == Fp12.ONE
 *       with a single batched Miller loop (`bn254.pairingBatch`, ~4× cheaper
 *       than four independent pairings).
 * WHY boolean-only: any parse error, off-curve point, non-subgroup point,
 *       non-canonical signal (≥ r), or pairing inequality all mean the same
 *       thing to a verifier — "this proof does not verify" — so every failure
 *       path returns `false`. Callers wanting typed errors wrap this
 *       (see commands/identity.ts `verifyProofOrThrow`).
 *
 * @param vkey          parsed snarkjs verification key (see zk/vkeys.ts).
 * @param publicSignals decimal strings; for the identity circuit EXACTLY
 *                      `[leafHash]` (`vkey.nPublic === 1`, IC length 2).
 * @param proof         `{ pi_a, pi_b, pi_c }` snarkjs decimal coordinates.
 */
export function verifyGroth16(
  vkey: Groth16Vkey,
  publicSignals: string[],
  proof: Groth16Proof,
): boolean {
  try {
    // The signal count must match the key: |IC| = nPublic + 1. A mismatch is
    // a statement-shape error, not a math error — reject before any parsing.
    if (!Array.isArray(publicSignals)) return false;
    if (!Array.isArray(vkey.IC) || vkey.IC.length !== publicSignals.length + 1) return false;
    if (vkey.nPublic !== publicSignals.length) return false;

    // Public signals must be canonical field elements (< r). snarkjs rejects
    // out-of-range signals too — keeping that behavior means our verdicts
    // agree with snarkjs on every input, tampered ones included.
    const signals = publicSignals.map(parseDec);
    for (const s of signals) {
      if (s >= SCALAR_FIELD_ORDER) return false;
    }

    // Proof + vkey points, with strict affine parsing and subgroup validation.
    const A = parseG1(proof.pi_a);
    const B = parseG2(proof.pi_b);
    const C = parseG1(proof.pi_c);
    const alpha1 = parseG1(vkey.vk_alpha_1);
    const beta2 = parseG2(vkey.vk_beta_2);
    const gamma2 = parseG2(vkey.vk_gamma_2);
    const delta2 = parseG2(vkey.vk_delta_2);

    // vk_x = IC[0] + Σ sᵢ·IC[i+1]. `multiplyUnsafe` is the right call for a
    // VERIFIER: scalars are public (no constant-time requirement) and it
    // accepts s = 0 (a legal, if degenerate, public signal) where the
    // constant-time `multiply` would throw.
    let vkX = parseG1(vkey.IC[0]);
    for (let i = 0; i < signals.length; i += 1) {
      vkX = vkX.add(parseG1(vkey.IC[i + 1]).multiplyUnsafe(signals[i]!));
    }

    // One batched Miller loop over the four pairs; final exponentiation is
    // applied once at the end (pairingBatch default). pairingBatch itself
    // re-asserts validity and throws on the point at infinity — any such
    // throw lands in the catch below as `false`.
    const result = bn254.pairingBatch([
      { g1: A.negate(), g2: B },
      { g1: alpha1, g2: beta2 },
      { g1: vkX, g2: gamma2 },
      { g1: C, g2: delta2 },
    ]);
    return bn254.fields.Fp12.eql(result, bn254.fields.Fp12.ONE);
  } catch {
    // Malformed input of ANY kind = the proof does not verify. Never throw raw.
    return false;
  }
}
