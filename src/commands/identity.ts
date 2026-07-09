/**
 * shuriken-sdk — client-side identity proof verification (`ninja.identity`).
 *
 * WHAT: REAL, offline Groth16 verification of `metanet-zk-identity-v1` proof
 *       envelopes. `verifyIdentityProof(envelope, canonicalId, pub)` returns a
 *       boolean; `verifyProofOrThrow(...)` throws a typed
 *       `NinjaError('ERR_PROOF_INVALID')` naming the failing purpose+reason.
 *       `makeIdentity()` wraps both as the `ninja.identity` namespace.
 * WHY:  proofs the parent mints (via connect / generate-proof) are
 *       self-verifiable: an app can confirm — offline, without trusting the
 *       wire or re-contacting the parent — that a ProofEnvelope actually binds
 *       a purpose public key to a canonicalId. The math mirrors the platform's
 *       authoritative verifier (metanet_back/src/services/identityZkVerifier.js):
 *       the verifier RECOMPUTES the single public signal (leafHash) from the
 *       public inputs and never trusts anything prover-supplied beyond the
 *       three proof points.
 *
 * VERIFICATION INPUTS — why `pub` is a parameter: the wire envelope carries
 * `{ scheme, purpose, seedCommitment, proof, assetId? }` but NOT the purpose
 * public key; the pub travels on the identity entry that BEARS the proof
 * (`me.bsv.pub`, `me.app.pub`, `bundle.pub`, …). The leafHash commits to that
 * key, so verification without it is impossible — exactly like the platform's
 * `verifyAssetProof({ canonicalId, pub, proof, ... })`. Callers pass the pub
 * from the same trusted-context slot the envelope came from.
 */

import type { ProofEnvelope } from '../types';
import { NinjaError, isNinjaError } from '../errors';
import {
  ASSET_PURPOSE_CURVES,
  IDENTITY_PURPOSE_CURVES,
  IDENTITY_PURPOSE_LABELS_V1,
  IDENTITY_ZK_SCHEME,
  CURVE_TAGS,
  type CurveName,
  computeLeafHash,
  computePubCommit,
  decodeIdentityCanonicalId,
  labelToField,
  paddedPublicKeyBytes,
} from '../zk/spec';
import { verifyGroth16 } from '../zk/groth16';
import { getVerifiedVkey } from '../zk/vkeys';

/**
 * Structural sanity checks on a ProofEnvelope.
 *
 * WHAT: returns true iff the envelope has the expected scheme, a Groth16 proof
 *       with the three point arrays populated, and a non-empty seed commitment.
 * WHY:  rejects obviously malformed or wrong-scheme envelopes (e.g. a truncated
 *       proof, or a proof minted for a different scheme) before any field math
 *       runs. Exact point shapes/lengths are the pairing parser's concern.
 */
function isWellFormed(proof: ProofEnvelope): boolean {
  if (proof.scheme !== IDENTITY_ZK_SCHEME) return false;
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

/** Map the wire `algorithm` tag ('ec' | 'ed') to the Groth16 curve / vkey. */
const ALGORITHM_CURVE: Readonly<Record<string, CurveName>> = Object.freeze({
  ec: 'Secp256k1',
  ed: 'Ed25519',
});

/**
 * Resolve an envelope's purpose to its circuit label string + curve.
 *
 * CURVE — the envelope is SELF-DESCRIBING: the parent stamps `algorithm`
 * (`'ec'` secp256k1 | `'ed'` ed25519) on every proof so the verifier picks the
 * right vkey without hardcoding a purpose→curve table. We read `algorithm`
 * first; the purpose→curve map is only a compatibility fallback for an older
 * parent that didn't send it (and it is what lets a NEW/custom purpose verify
 * with no SDK release — the parent tells us the curve).
 *
 * LABEL — identity purposes (bsv/icp/kda/content + platform-internal
 * mutation/session) map to their fixed `metanet:purpose:<name>:v1` label.
 * Asset purposes (app/apps/username/chat) REQUIRE `assetId` and bake it into
 * the label VERBATIM — `metanet:purpose:<purpose>:<assetId>:v1` — matching the
 * platform's ASSET_PURPOSE_LABEL_BUILDERS_V1 (for `chat` the assetId embeds the
 * rotation epoch as `<username>:e<epoch>`). Unknown purposes throw: verifying
 * against a guessed label would silently pass nothing and fail everything.
 */
function resolvePurpose(envelope: ProofEnvelope): { label: string; curve: CurveName } {
  const purpose = envelope.purpose;

  // Self-describing curve from the wire tag; fall back to the purpose map.
  const taggedCurve =
    typeof envelope.algorithm === 'string' ? ALGORITHM_CURVE[envelope.algorithm] : undefined;

  const identityLabel = IDENTITY_PURPOSE_LABELS_V1[purpose];
  if (identityLabel !== undefined) {
    const curve = taggedCurve ?? IDENTITY_PURPOSE_CURVES[purpose];
    if (!curve) throw new Error(`no curve configured for identity purpose '${purpose}'`);
    return { label: identityLabel, curve };
  }

  const assetLabelCurve = ASSET_PURPOSE_CURVES[purpose];
  // An unknown purpose is still verifiable IF the envelope tags its curve AND
  // carries an assetId (the parent is the source of truth for both).
  const curve = taggedCurve ?? assetLabelCurve;
  if (curve !== undefined) {
    const assetId = envelope.assetId;
    if (typeof assetId !== 'string' || assetId.length === 0) {
      throw new Error(`asset purpose '${purpose}' requires envelope.assetId`);
    }
    return { label: `metanet:purpose:${purpose}:${assetId}:v1`, curve };
  }

  throw new Error(`unknown proof purpose '${purpose}' (and no envelope.algorithm to resolve its curve)`);
}

/**
 * Verify a Groth16 identity/asset proof binds `pub` to `canonicalId` — or
 * throw a typed error naming the failure.
 *
 * WHAT (mirrors identityZkVerifier.verifyAssetProof / identityPurposeStatement):
 *   1. structural envelope check;
 *   2. seedCommitment := decode(canonicalId) (base58, version byte 0x01,
 *      < BN254 modulus) — and it must equal `envelope.seedCommitment` (a
 *      mismatched pair means the proof was minted for a DIFFERENT identity);
 *   3. purposeTag := labelToField(label(purpose[, assetId]));
 *   4. pubCommit / leafHash recomputed from the padded `pub` bytes;
 *   5. Groth16 pairing check against the SHA-pinned embedded vkey for the
 *      purpose's curve, with `[leafHash]` as the sole public signal.
 *
 * WHY throw-based: `connect()`/`proof.generate()` verify received proofs
 * out-of-the-box and must REJECT with a precise, localizable code when a
 * proof is bad — a tampered/lying source, since the payload signature already
 * passed. Every failure throws `NinjaError('ERR_PROOF_INVALID')` with a
 * `'<purpose>: <reason>'` hint. `ERR_VKEY_INTEGRITY` (a corrupted/tampered
 * SDK bundle) is deliberately NOT converted — it must surface as itself.
 *
 * @param envelope    the ProofEnvelope to verify.
 * @param canonicalId the identity the proof must bind to (hyphen-grouped
 *                    base58; decodes to the circuit seedCommitment).
 * @param pub         the purpose PUBLIC KEY hex the proof commits to —
 *                    compressed SEC1 (33 bytes) for secp256k1 purposes,
 *                    32 bytes for Ed25519 (icp/kda). Comes from the identity
 *                    entry bearing the proof (`me.bsv.pub`, `bundle.pub`, …).
 */
export function verifyProofOrThrow(
  envelope: ProofEnvelope,
  canonicalId: string,
  pub: string,
): void {
  const purpose = String(envelope?.purpose ?? 'unknown');
  const fail = (reason: string): never => {
    throw new NinjaError('ERR_PROOF_INVALID', { hint: `${purpose}: ${reason}` });
  };

  if (!envelope || !isWellFormed(envelope)) {
    fail('malformed proof envelope (scheme/seedCommitment/proof points)');
  }
  if (!canonicalId) fail('missing canonicalId to verify against');
  if (typeof pub !== 'string' || pub.length === 0) {
    fail('missing purpose public key (pub) to verify against');
  }

  // 2. canonicalId → seedCommitment, cross-checked against the envelope's own
  //    claim (same rule as the platform's seedCommitmentForDocument).
  let seedCommitment = '';
  try {
    seedCommitment = decodeIdentityCanonicalId(canonicalId);
  } catch (e) {
    fail(`invalid canonicalId: ${(e as Error).message}`);
  }
  if (String(envelope.seedCommitment) !== seedCommitment) {
    fail('envelope seedCommitment does not match canonicalId');
  }

  // 3–4. Rebuild the public statement: purposeTag → pubCommit → leafHash.
  let leafHash = '';
  let curve: CurveName = 'Secp256k1';
  try {
    const resolved = resolvePurpose(envelope);
    curve = resolved.curve;
    const purposeTag = labelToField(resolved.label);
    const curveTag = CURVE_TAGS[curve];
    const publicKeyBytes = paddedPublicKeyBytes(pub, curve);
    const pubCommit = computePubCommit({ purposeTag, curveTag, publicKeyBytes });
    leafHash = computeLeafHash({ seedCommitment, purposeTag, curveTag, pubCommit });
  } catch (e) {
    fail((e as Error).message);
  }

  // 5. The pairing check against the SHA-pinned embedded vkey. getVerifiedVkey
  //    throws ERR_VKEY_INTEGRITY on a corrupted bundle — let it propagate.
  const vkey = getVerifiedVkey(curve);
  if (!verifyGroth16(vkey, [leafHash], envelope.proof)) {
    fail('Groth16 pairing check failed');
  }
}

/**
 * Boolean form of {@link verifyProofOrThrow} — `true` iff the proof verifies.
 *
 * WHY the one exception: `ERR_VKEY_INTEGRITY` still propagates. A corrupted /
 * tampered SDK bundle must FAIL CLOSED — collapsing it into `false` would look
 * identical to "bad proof" and could be swallowed by a caller that treats
 * false as a soft condition. Everything else (malformed envelope, unknown
 * purpose, missing assetId, bad canonicalId, pairing failure) is `false`.
 */
export function verifyIdentityProof(
  envelope: ProofEnvelope,
  canonicalId: string,
  pub: string,
): boolean {
  try {
    verifyProofOrThrow(envelope, canonicalId, pub);
    return true;
  } catch (e) {
    if (isNinjaError(e) && e.code === 'ERR_VKEY_INTEGRITY') throw e;
    return false;
  }
}

/**
 * Build the `ninja.identity` sugar object.
 *
 * WHAT: returns `{ verifyProof, verifyProofOrThrow }`.
 * WHY:  no dependencies are injected — verification is entirely local (the
 *       vkeys are embedded and SHA-pinned) — but we keep the factory shape
 *       uniform with the other command modules so index.ts assembles every
 *       namespace the same way. The same functions are exported top-level for
 *       server-side/Node reuse without constructing a client.
 */
export function makeIdentity(): {
  verifyProof(proof: ProofEnvelope, canonicalId: string, pub: string): boolean;
  verifyProofOrThrow(proof: ProofEnvelope, canonicalId: string, pub: string): void;
} {
  return {
    verifyProof: verifyIdentityProof,
    verifyProofOrThrow,
  };
}
