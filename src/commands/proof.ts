/**
 * shuriken-sdk — `generate-proof` command sugar (`ninja.proof`).
 *
 * WHAT: `makeProof` builds `{ generate(params) }` over the `generate-proof`
 *       wire method — the APP-identity-proof-only shortcut — and VERIFIES the
 *       returned Groth16 bundle locally before resolving (out-of-the-box
 *       proof verification; opt out via `verifyProof: false`).
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
import type { GenerateProofParams, GenerateProofResult, ProofEnvelope } from '../types';
import { NinjaError } from '../errors';
import { verifyProofOrThrow } from './identity';

/**
 * Build the `ninja.proof` sugar object.
 *
 * WHAT: returns `{ generate }`, a typed wrapper over
 *       `codec.call('generate-proof', …)` plus local verification of the
 *       returned bundle.
 * WHY:  the single WIRE param (`reason`) maps 1:1 to the manifest request
 *       schema; `verifyProof` is a client-side flag and is STRIPPED before the
 *       wire call. The result carries the raw Groth16 proof plus the binding
 *       fields (`canonicalId`, `pub`, `seedCommitment`, `appId`, `appUrl`) a
 *       verifier needs — the SDK assembles the ProofEnvelope and runs the same
 *       pinned-vkey pairing check the platform runs, so a resolved promise
 *       already means "cryptographically valid proof", not just "the parent
 *       answered".
 */
export function makeProof(codec: Codec): { generate(params?: GenerateProofParams): Promise<GenerateProofResult> } {
  return {
    /**
     * Mint the APP-identity Groth16 zero-knowledge proof (shortcut) and
     * verify it locally before resolving.
     *
     * Proofs for other purposes are requested via the re-callable
     * `ninja.connect({ request, proofs })` (approved items resolve silently,
     * new items re-prompt the full list; approvals persist, denials are
     * per-visit).
     *
     * VERIFICATION: the parent returns the app-proof bundle
     * `{ canonicalId, pub, proof, seedCommitment, appId, appUrl }`. The SDK
     * assembles the `metanet-zk-identity-v1` envelope (purpose `app`,
     * assetId = bundle.appId) and runs the Groth16 pairing check against the
     * embedded SHA-pinned vkey. A bad bundle REJECTS with `ERR_PROOF_INVALID`
     * (the response signature already passed, so a bad proof means a
     * tampered/lying source). Opt out with `verifyProof: false` (client-side
     * flag, never sent) only if you re-verify elsewhere.
     *
     * @param params optional human-readable `reason` (shown in the consent
     *               overlay) + the local `verifyProof` opt-out. App proofs
     *               require a V1 identity — a V0 user yields
     *               `app_proof_requires_v1`.
     * @returns the verified proof bundle: canonicalId, session pub, Groth16
     *          proof, seed commitment, and the binding appId/appUrl.
     */
    async generate(params: GenerateProofParams = {}): Promise<GenerateProofResult> {
      // Split the client-side flag off the wire params: the parent's request
      // schema is `{ reason? }` and must receive nothing else.
      const { verifyProof = true, ...wireParams } = params;

      const bundle = await codec.call<GenerateProofResult>('generate-proof', wireParams);

      if (verifyProof) {
        // The app proof's assetId IS the bundle's appId (`hash160(appUrl)` or
        // `<appId>:<hash160(salt)>`) — the label bakes it verbatim. Without it
        // the statement cannot be rebuilt, so its absence is a proof failure.
        if (typeof bundle.appId !== 'string' || bundle.appId.length === 0) {
          throw new NinjaError('ERR_PROOF_INVALID', {
            method: 'generate-proof',
            hint: 'app: bundle is missing appId (the app-proof assetId) — cannot rebuild the statement',
          });
        }
        const envelope: ProofEnvelope = {
          scheme: 'metanet-zk-identity-v1',
          purpose: 'app',
          assetId: bundle.appId,
          seedCommitment: bundle.seedCommitment,
          proof: bundle.proof,
        };
        // Throws ERR_PROOF_INVALID on any failure; ERR_VKEY_INTEGRITY (a
        // corrupted SDK bundle) propagates as itself — fail closed.
        verifyProofOrThrow(envelope, bundle.canonicalId, bundle.pub);
      }

      return bundle;
    },
  };
}
