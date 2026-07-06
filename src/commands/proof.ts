/**
 * shuriken-sdk — `generate-proof` command sugar (`ninja.proof`).
 *
 * WHAT: `makeProof` builds `{ generate(params) }` over the `generate-proof`
 *       wire method — the APP-identity-proof-only shortcut.
 * WHY:  minting a Groth16 identity proof is a consent-gated, wallet-backed
 *       action that binds the current session to the user's canonicalId. This
 *       method only ever mints the `app`-purpose proof (there is deliberately
 *       no `purpose` param — the parent ignores anything else). App proofs
 *       require a V1 identity: the parent enforces that and returns
 *       `app_proof_requires_v1` for a V0 identity, so the SDK forwards `reason`
 *       and lets that precise code surface to the caller (who can branch to a
 *       V1 upgrade prompt).
 *
 *       For any OTHER purpose (bsv/icp/kda/content, or a future namespace), the
 *       canonical way is `ninja.connect({ request, proofs })` — which is
 *       RE-CALLABLE to request identities/proofs later: already-approved items
 *       resolve silently (no overlay), new items re-prompt the user with the
 *       full list. Approvals persist across visits; denials are per-visit.
 */

import type { Codec } from '../protocol/codec';
import type { GenerateProofParams, GenerateProofResult } from '../types';

/**
 * Build the `ninja.proof` sugar object.
 *
 * WHAT: returns `{ generate }`, a typed wrapper over
 *       `codec.call('generate-proof', …)`.
 * WHY:  the single param (`reason`) maps 1:1 to the manifest request schema, so
 *       we forward it unchanged. The result carries the raw Groth16 proof
 *       plus the binding fields (`canonicalId`, `pub`, `seedCommitment`) a
 *       verifier needs — clients that want to check it locally can pass the
 *       assembled envelope to `ninja.identity.verifyProof`.
 */
export function makeProof(codec: Codec): { generate(params?: GenerateProofParams): Promise<GenerateProofResult> } {
  return {
    /**
     * Mint the APP-identity Groth16 zero-knowledge proof (shortcut).
     *
     * Proofs for other purposes are requested via the re-callable
     * `ninja.connect({ request, proofs })` (approved items resolve silently,
     * new items re-prompt the full list; approvals persist, denials are
     * per-visit).
     *
     * @param params optional human-readable `reason` (shown in the consent
     *               overlay). App proofs require a V1 identity — a V0 user
     *               yields `app_proof_requires_v1`.
     * @returns the proof envelope fields: canonicalId, session pub, Groth16
     *          proof, seed commitment, and the binding appId/appUrl.
     */
    generate(params: GenerateProofParams = {}): Promise<GenerateProofResult> {
      return codec.call<GenerateProofResult>('generate-proof', params);
    },
  };
}
