/**
 * shuriken-sdk — `connect` command sugar.
 *
 * WHAT: `makeConnect` builds the `ninja.connect(params)` function that performs
 *       the identity handshake with the parent and returns a version-normalized
 *       {@link ConnectResult}.
 * WHY:  connection is the ONE call that establishes the session verification key.
 *       Every subsequent response's signature is checked against that key, so
 *       `connect` must (a) map the ergonomic params onto the parent's exact wire
 *       shape, (b) fire the raw `connection` wire call, (c) normalize the
 *       V0/V1/anonymous payload into a discriminated union, and (d) publish the
 *       session (pub + version + genericUseSeed) into the codec BEFORE it hands
 *       the result back — if we returned first, an eager caller could fire
 *       `pay()` before the codec knew which key verifies the response, and every
 *       reply would spuriously reject with ERR_SIGNATURE. Ordering is load-bearing.
 */

import type { CallWithEnvelope, ConnectParams, ConnectResult, ProofEnvelope } from '../types';
import type { Codec, Session } from '../protocol/codec';
import { normalizeConnection, sessionPubOf, sessionVersionOf } from '../protocol/normalize';
import { NinjaError } from '../errors';
import { verifyProofOrThrow } from './identity';

/**
 * Deadline for a consent-bearing connect (identities/proofs requested): the
 * user may take their time on the consent overlay, and an approved proof can
 * trigger first-time Groth16 proving (zkey download + prove — minutes, with
 * progress shown platform-side). 10 minutes; override per call via
 * `ConnectParams.timeoutMs`. A bare connect keeps the protocol default (30s).
 */
export const CONSENT_CONNECT_TIMEOUT_MS = 600_000;

/**
 * Map the ergonomic {@link ConnectParams} onto the parent's exact `connection`
 * wire shape.
 *
 * WHAT: `{ request, proofs, salt, navbg }` becomes
 *       `{ identities: { bsv: { proof? } … }, appIdentity: { proof? }, salt?, navbg? }`.
 * WHY:  the parent's V1 request parser (connectionHandler.normalizeV1ConnectionRequest)
 *       reads *presence* of a purpose key under `identities` as "requested", and a
 *       boolean `proof` flag inside each entry; the app's own proof travels under
 *       `appIdentity.proof`. The SDK's `request`/`proofs` arrays are far harder to
 *       misuse (no nested boolean soup), so we translate here — in exactly one
 *       place — instead of exposing the raw shape. A V0 parent simply ignores the
 *       extra fields, so sending them is always safe.
 */
export function toConnectionWireParams(params: ConnectParams): Record<string, unknown> {
  const wire: Record<string, unknown> = {};

  // Presence of a purpose key under `identities` = "share this identity". A
  // proof request for that same purpose sets its `proof` flag (harmless if the
  // purpose wasn't in `request`: the parent treats proof-bearing entries as
  // requested). The loop is purpose-agnostic on purpose: any core purpose
  // (bsv/icp/kda/content) — and any future/custom namespace — is forwarded
  // untouched; only 'app' is special-cased (it rides on appIdentity below).
  const identities: Record<string, { proof?: boolean }> = {};
  for (const chain of params.request ?? []) {
    identities[chain] = identities[chain] ?? {};
  }
  for (const purpose of params.proofs ?? []) {
    if (purpose === 'app') continue; // the app proof rides on appIdentity below
    identities[purpose] = { ...(identities[purpose] ?? {}), proof: true };
  }
  if (Object.keys(identities).length > 0) wire['identities'] = identities;

  // The app identity is always shared (it's the session signer); this flag only
  // asks for its Groth16 proof.
  if ((params.proofs ?? []).includes('app')) wire['appIdentity'] = { proof: true };

  // Wallet-level info request (V1): the parent answers with `payload.wallets`
  // (`[{ chain, address|principal|account, pub }]`). Sent verbatim — the legacy
  // scaffold SDK exposed exactly this array and apps (and the compat layer)
  // depend on it. A V0 parent ignores it like the other V1 declaration fields.
  if (params.wallets !== undefined && params.wallets.length > 0) {
    wire['wallets'] = params.wallets;
  }

  // Pass-through fields the parent validates itself (salt: strict regex ->
  // invalid_salt; navbg: CSS-color sanitizer). We never pre-mangle them.
  if (params.salt !== undefined) wire['salt'] = params.salt;
  if (params.navbg !== undefined) wire['navbg'] = params.navbg;

  return wire;
}

/**
 * Verify EVERY ZK proof envelope a normalized V1 connection result carries,
 * against the result's own canonicalId — out-of-the-box, before the connect
 * resolves.
 *
 * WHAT: walks the canonical `me.proofs` map AND any per-identity `.proof`
 *       envelope the normalizer didn't merge into it (the map wins on
 *       duplicates, but a nested envelope that DIFFERS from the map entry is
 *       verified too — an attacker must not be able to hide a forged copy in
 *       the less-read slot). Each envelope is verified with the purpose
 *       entry's own `pub` (`me.app.pub` for `app`, `me.<purpose>.pub`
 *       otherwise) via {@link verifyProofOrThrow}.
 * WHY reject-on-failure: the connection payload's SIGNATURE already passed,
 *       so a proof that fails local verification means the source is tampered
 *       or lying about identity binding — resolving the connect anyway would
 *       hand the app a "verified" identity that isn't. V0 and anonymous
 *       results carry no ZK proofs, so they pass through untouched.
 *
 * @throws NinjaError('ERR_PROOF_INVALID') naming the purpose + reason; or
 *         ERR_VKEY_INTEGRITY if the SDK's embedded vkey pin fails (corrupted
 *         bundle — fail closed).
 */
export function verifyConnectionProofs(result: ConnectResult): void {
  if (result.anonymous || result.version !== 1) return;

  // Collect every distinct envelope with its purpose. `me.proofs` is the
  // canonical merged map; nested `.proof` objects are re-checked only when
  // they are not the exact object already collected (Set identity is enough:
  // the normalizer copies references, never clones).
  const jobs: Array<{ purpose: string; envelope: ProofEnvelope }> = [];
  const seen = new Set<ProofEnvelope>();
  for (const [purpose, envelope] of Object.entries(result.proofs)) {
    if (!envelope) continue;
    jobs.push({ purpose, envelope });
    seen.add(envelope);
  }
  for (const [purpose, value] of Object.entries(result)) {
    if (typeof value !== 'object' || value === null) continue;
    const nested = (value as { proof?: unknown }).proof as ProofEnvelope | undefined;
    if (!nested || typeof nested !== 'object') continue;
    if (nested.scheme !== 'metanet-zk-identity-v1') continue;
    if (seen.has(nested)) continue;
    jobs.push({ purpose, envelope: nested });
    seen.add(nested);
  }

  for (const { purpose, envelope } of jobs) {
    // The pub travels on the identity entry BEARING the proof — the envelope
    // itself never carries it (see commands/identity.ts). A proof for a
    // purpose whose entry shared no pub is unverifiable ⇒ invalid.
    const entry = (result as Record<string, unknown>)[purpose];
    const pub =
      typeof entry === 'object' && entry !== null && typeof (entry as { pub?: unknown }).pub === 'string'
        ? ((entry as { pub: string }).pub)
        : '';
    if (!pub) {
      throw new NinjaError('ERR_PROOF_INVALID', {
        method: 'connection',
        hint: `${purpose}: proof present but no public key was shared for this purpose — cannot verify`,
      });
    }
    verifyProofOrThrow(envelope, result.canonicalId, pub);
  }
}

/**
 * Build the `ninja.connect` sugar.
 *
 * WHAT: returns an async function that calls the `connection` method, normalizes
 *       the response, lifts the envelope's top-level extras, seeds the session,
 *       and resolves the normalized identity.
 * WHY:  factored as a factory (over a plain function) so `src/index.ts` can inject
 *       the live `codec` and the session-setter that mutates the shared session
 *       store the codec reads on every verify. Keeping `setSession` external (not
 *       reaching into the codec here) preserves the single-writer invariant.
 *
 * @param codec      the wire engine; `call('connection', …)` does the round trip.
 * @param setSession publishes `{ pub, version, genericUseSeed }` into the shared
 *                   session store the codec's `getSession()` reads when verifying
 *                   signatures (and `pay.bsv` reads when signing broadcasts).
 * @returns `(params?) => Promise<ConnectResult>`.
 */
export function makeConnect(
  codec: Codec,
  setSession: (s: Session) => void,
): (params?: ConnectParams) => Promise<ConnectResult> {
  return async function connect(params: ConnectParams = {}): Promise<ConnectResult> {
    // Fire the raw wire call with the translated params, asking the codec for the
    // FULL envelope: the parent attaches `genericUseSeed` and `icIdentityPackage`
    // at the envelope's top level — OUTSIDE the signed payload — on both V0 and
    // V1 (connectionHandler.js lines 337 / 518), so payload-only would lose them.
    // The payload itself is version-polymorphic (V0 wallet vs V1 identities vs
    // anonymous) — normalizeConnection disambiguates it. Signature note: at this
    // point the session pub is still null (this IS the message that establishes
    // it), so signature.ts short-circuits to `true` and the origin check gates.
    const wire = toConnectionWireParams(params);

    // Deadline: a bare connect (app identity only) is answered immediately by
    // the parent, so the protocol default (30s) applies. Anything requesting
    // identities/proofs can legitimately take MINUTES — the request may sit
    // behind the consent overlay waiting for the user, and an approved proof
    // triggers first-time Groth16 proving (zkey download + prove) that the
    // platform surfaces as per-proof progress rows while this call stays
    // pending. Timing out at 30s mid-consent produced spurious ERR_TIMEOUTs,
    // so consent-bearing connects get the long deadline (caller-overridable
    // via params.timeoutMs).
    const needsConsent = wire['identities'] !== undefined || wire['appIdentity'] !== undefined;
    const timeoutMs = params.timeoutMs ?? (needsConsent ? CONSENT_CONNECT_TIMEOUT_MS : undefined);

    const { payload, envelope } = await codec.call<CallWithEnvelope<Record<string, unknown>>>(
      'connection',
      wire,
      { withEnvelope: true, ...(timeoutMs !== undefined ? { timeoutMs } : {}) },
    );

    // Map the raw payload onto the ConnectResult union (+ `.raw` escape hatch).
    // This is where `version: 0 | 1 | undefined` becomes a real discriminant so
    // downstream code physically cannot read a V1 field off a V0 identity.
    const result = normalizeConnection(payload);

    // Lift the documented top-level extras onto the result. `genericUseSeed` is
    // the fixed per-user-per-app(-salt) seed (BOTH versions; V1 re-keys it with
    // the salt); `icIdentityPackage` is the time-bounded ICP delegation.
    const genericUseSeed =
      typeof envelope['genericUseSeed'] === 'string' ? envelope['genericUseSeed'] : undefined;
    if (genericUseSeed !== undefined) result.genericUseSeed = genericUseSeed;
    if (envelope['icIdentityPackage'] !== undefined) {
      result.icIdentityPackage = envelope['icIdentityPackage'];
    }

    // OUT-OF-THE-BOX proof verification (default ON): every ZK proof envelope
    // the response carries is verified against `me.canonicalId` BEFORE the
    // session is seeded or the result returned. A failure REJECTS the connect
    // with ERR_PROOF_INVALID — the payload signature already passed, so a bad
    // proof means a tampered/lying source, and seeding a session from it would
    // bless every later response from that source. `verifyProofs: false` is
    // the documented opt-out for callers that re-verify server-side.
    if (params.verifyProofs !== false) {
      verifyConnectionProofs(result);
    }

    // Seed the session BEFORE returning. sessionPubOf picks the correct key per
    // version (V0 wallet.publicKeyHex, V1 app.pub, anonymous null); every future
    // response is verified against exactly this key. genericUseSeed rides along
    // so `pay.bsv({ broadcast: true })` can sign the broadcast-API request — and
    // rotates atomically with the key on every (re)connect / salt change.
    setSession({
      pub: sessionPubOf(result),
      version: sessionVersionOf(result),
      genericUseSeed: genericUseSeed ?? null,
    });

    return result;
  };
}
