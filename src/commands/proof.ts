/**
 * shuriken-sdk — `generate-proof` command sugar (`ninja.proof`).
 *
 * WHAT: `makeProof` builds `{ generate(params) }` over the `generate-proof`
 *       wire method.
 * WHY:  minting a Groth16 identity proof is a consent-gated, wallet-backed
 *       action that binds the current session to the user's canonicalId. The
 *       app-purpose proof additionally requires a V1 identity — the parent
 *       enforces that and returns `app_proof_requires_v1` for a V0 identity, so
 *       the SDK forwards purpose/reason and lets that precise code surface to the
 *       caller (who can branch to a V1 upgrade prompt). Prefer batching proofs
 *       via `connect({ proofs })`; this method exists for the on-demand case.
 */

import type { Codec } from '../protocol/codec';
import type { GenerateProofParams, GenerateProofResult } from '../types';

/**
 * Build the `ninja.proof` sugar object.
 *
 * WHAT: returns `{ generate }`, a typed wrapper over
 *       `codec.call('generate-proof', …)`.
 * WHY:  the params (`reason`, `purpose`) map 1:1 to the manifest request schema,
 *       so we forward them unchanged. The result carries the raw Groth16 proof
 *       plus the binding fields (`canonicalId`, `pub`, `seedCommitment`) a
 *       verifier needs — clients that want to check it locally can pass the
 *       assembled envelope to `ninja.identity.verifyProof`.
 */
export function makeProof(codec: Codec): { generate(params?: GenerateProofParams): Promise<GenerateProofResult> } {
  return {
    /**
     * Mint a Groth16 zero-knowledge identity proof.
     *
     * @param params optional human-readable `reason` (shown in the consent
     *               overlay) and `purpose` (`app` requires a V1 identity).
     * @returns the proof envelope fields: canonicalId, session pub, Groth16
     *          proof, seed commitment, and (for app proofs) appId/appUrl.
     */
    generate(params: GenerateProofParams = {}): Promise<GenerateProofResult> {
      return codec.call<GenerateProofResult>('generate-proof', params);
    },
  };
}
