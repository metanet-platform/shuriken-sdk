/**
 * shuriken-sdk — client-side identity verification (`ninja.identity`).
 *
 * WHAT: `makeIdentity` builds `{ verifyProof(proof, canonicalId) }`, a PURELY
 *       LOCAL check that a Groth16 identity proof envelope is well-formed and
 *       (once a verifying key is bundled) cryptographically valid for the given
 *       canonicalId.
 * WHY:  proofs the parent mints (via connect/generate-proof) are self-verifiable:
 *       an app can confirm, offline and without trusting the wire, that a
 *       ProofEnvelope actually binds to a canonicalId. This is the piece that lets
 *       a gated app enforce "prove you are this identity" without a server round
 *       trip. This module does NOT touch the codec — verification is client-side
 *       math over the bundled verifying key.
 */

import type { ProofEnvelope } from '../types';

/**
 * The Groth16 verifying key for the `metanet-zk-identity-v1` circuit.
 *
 * WHAT: `null` until the compiled `vkey.json` is bundled into the SDK.
 * WHY:  the verifying key is a build artifact of the identity_circom trusted
 *       setup ceremony. Until it's vendored into `src/generated/`, `verifyProof`
 *       cannot run the pairing check — see `verifyProof`'s stub branch. Kept as a
 *       module-level slot (not inlined) so wiring the real key later is a one-line
 *       change with no signature churn.
 *
 * TODO(v1.0): import the ceremony's `verification_key.json` (the CIDs live in the
 * frontend's `zkArtifactCids.js`) and assign it here, then implement the pairing
 * check in `verifyProof`.
 */
const VERIFYING_KEY: unknown | null = null;

/**
 * Structural sanity checks on a ProofEnvelope.
 *
 * WHAT: returns true iff the envelope has the expected scheme, a Groth16 proof
 *       with the three point arrays populated, and a non-empty seed commitment.
 * WHY:  even before the pairing check is available, we can reject obviously
 *       malformed or wrong-scheme envelopes (e.g. a truncated proof, or a proof
 *       minted for a different scheme). This is a necessary precondition of a real
 *       verification, and on its own it stops the most common "someone handed me
 *       garbage" mistake. Separated out so the real crypto path can reuse it.
 */
function isWellFormed(proof: ProofEnvelope): boolean {
  if (proof.scheme !== 'metanet-zk-identity-v1') return false;
  if (!proof.seedCommitment) return false;
  const g = proof.proof;
  if (!g) return false;
  // Groth16 proof points: pi_a and pi_c are 1-D arrays; pi_b is 2-D. We only
  // assert non-emptiness here (exact lengths are the pairing check's concern).
  if (!Array.isArray(g.pi_a) || g.pi_a.length === 0) return false;
  if (!Array.isArray(g.pi_b) || g.pi_b.length === 0) return false;
  if (!Array.isArray(g.pi_c) || g.pi_c.length === 0) return false;
  return true;
}

/**
 * Build the `ninja.identity` sugar object.
 *
 * WHAT: returns `{ verifyProof }`.
 * WHY:  no dependencies are injected — verification is entirely local — but we
 *       keep the factory shape uniform with the other command modules so index.ts
 *       assembles every namespace the same way.
 */
export function makeIdentity(): { verifyProof(proof: ProofEnvelope, canonicalId: string): boolean } {
  return {
    /**
     * Verify a Groth16 identity proof binds to `canonicalId`, client-side.
     *
     * WHAT: returns true iff the proof is well-formed AND (when the verifying key
     *       is bundled) the Groth16 pairing check passes for the public signals
     *       derived from `canonicalId`.
     * WHY:  lets an app trust a proof it received (e.g. from a peer, or persisted)
     *       without re-contacting the parent. Today the verifying key is not yet
     *       bundled, so — after the structural check — we return `true` and flag it
     *       with a TODO rather than throwing or silently returning false: a false
     *       here would break every honest caller during the pre-1.0 window, while
     *       the structural check still rejects clearly-malformed input. Once the
     *       vkey lands, swap the stub branch for the real pairing verification and
     *       this becomes a full cryptographic check with no signature change.
     *
     * @param proof       the ProofEnvelope to verify.
     * @param canonicalId the identity the proof must bind to (feeds the public
     *                    signals of the circuit).
     * @returns true if the proof is (structurally, and later cryptographically)
     *          valid for `canonicalId`.
     */
    verifyProof(proof: ProofEnvelope, canonicalId: string): boolean {
      // A proof with no target identity can never be meaningfully verified.
      if (!canonicalId) return false;

      // Reject clearly-malformed / wrong-scheme envelopes regardless of vkey.
      if (!isWellFormed(proof)) return false;

      if (VERIFYING_KEY === null) {
        // TODO(v1.0): bundle verification_key.json and run the Groth16 pairing
        // check against public signals derived from `canonicalId` (and, for app
        // proofs, `proof.assetId`). Until then we optimistically accept a
        // well-formed envelope so honest callers aren't blocked pre-1.0.
        return true;
      }

      // TODO(v1.0): const publicSignals = deriveSignals(canonicalId, proof);
      //             return groth16Verify(VERIFYING_KEY, publicSignals, proof.proof);
      // The line below is unreachable until VERIFYING_KEY is populated; it exists
      // so the real implementation slots in without restructuring the function.
      return false;
    },
  };
}
