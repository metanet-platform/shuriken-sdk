/**
 * shuriken-sdk — connection-response normalization (the V0/V1 disambiguator).
 *
 * WHAT: turns the parent's version-polymorphic `connection-response` payload into
 *       the typed, discriminated {@link ConnectResult} union (V0 wallet / V1
 *       purpose-scoped identities / anonymous), plus two selectors —
 *       `sessionPubOf` and `sessionVersionOf` — that pick the exact key + version
 *       the codec verifies every later response against.
 * WHY:  this is THE correctness trap that fractured the ~15 hand-copied SDKs. The
 *       parent signs V0 responses with the root/session key (`wallet.publicKeyHex`)
 *       and V1 responses with the APP-specific key (`app.pub`). Reading the wrong
 *       one — or mixing V0 and V1 fields — makes every signature check spuriously
 *       fail (or, worse, pass against the wrong key). Modeling the result as a
 *       discriminated union means TypeScript FORCES a `version` check before any
 *       version-specific field can be read, and `.raw` keeps every original field
 *       reachable for forward-compat. There is deliberately NO key fallback chain:
 *       the version selects exactly one key; if it's absent that is a protocol bug
 *       that must surface, not be papered over.
 *
 * Zero dependencies beyond the shared type contract.
 */

import type { ChainKind, ConnectResult, NinjaIdentity, ProofEnvelope, ProofPurpose } from '../types';

/**
 * Normalize a raw `connection-response` payload into a {@link ConnectResult}.
 *
 * WHAT: inspects the payload's version discriminant (and its shape as a fallback)
 *       and returns the matching branch of the union, always with `connected` and
 *       the untouched `.raw` payload attached.
 * WHY:  the parent's payload is polymorphic — V0 carries a `wallet` object, V1
 *       carries `identities`/`app`, and an anonymous connection carries neither.
 *       Disambiguating ONCE here (rather than at every read site) is what makes
 *       the rest of the SDK version-safe. We prefer the explicit `version` field
 *       but fall back to structural detection (`wallet` present ⇒ V0, `identities`
 *       present ⇒ V1) so a parent that omits the field on the frozen wire still
 *       normalizes correctly (BUILD_SPEC §normalize).
 *
 * @param payload the raw connection-response payload (already envelope- and
 *                origin-verified by the codec; its signature is un-checkable here
 *                because this IS the message that establishes the session key).
 * @returns the discriminated {@link ConnectResult} (+ `.raw` escape hatch).
 */
export function normalizeConnection(payload: Record<string, unknown>): ConnectResult {
  // The explicit discriminant when present. `version` is the authoritative signal;
  // the structural checks below only cover a parent that omits it.
  const version = payload['version'];

  // ---- V0: single `wallet` object, root-key signed. --------------------------
  // Detected by `version === 0` OR the presence of a `wallet` object (the frozen
  // V0 wire never sends `version`, so the shape is the real signal there).
  const wallet = payload['wallet'];
  if (version === 0 || (isObject(wallet) && version !== 1)) {
    const w = (isObject(wallet) ? wallet : {}) as Record<string, unknown>;
    return {
      version: 0,
      anonymous: false,
      canonicalId: asString(payload['canonicalId']) ?? asString(w['canonicalId']) ?? '',
      wallet: {
        address: asString(w['address']) ?? '',
        publicKeyHex: asString(w['publicKeyHex']) ?? '',
        ...(asString(w['rootPrincipal']) !== undefined ? { rootPrincipal: asString(w['rootPrincipal'])! } : {}),
        ...(asString(w['bsvPubKey']) !== undefined ? { bsvPubKey: asString(w['bsvPubKey'])! } : {}),
        ...(asString(w['canonicalId']) !== undefined ? { canonicalId: asString(w['canonicalId'])! } : {}),
      },
      connected: true,
      raw: payload,
    };
  }

  // ---- V1: purpose-scoped identities, app-key signed. ------------------------
  // Detected by `version === 1` OR the presence of an `identities`/`app` block.
  const identities = payload['identities'];
  const app = payload['app'];
  if (version === 1 || isObject(identities) || isObject(app)) {
    // The purpose-scoped identity blocks live under `identities` (the frozen V1
    // shape); a parent may also hoist `app` to the top level. Reading from
    // `identities` first, then the top level, covers both without a fallback chain
    // that could pick the wrong key.
    const idBlock = isObject(identities) ? identities : payload;

    const appBlock = pickBlock(idBlock, 'app') ?? (isObject(app) ? app : undefined);

    // Assemble the V1 identity. Per-purpose blocks (bsv/icp/kda/content) are
    // optional; each is included only when the parent actually shared it, so an
    // app can narrow on `me.bsv` presence rather than reading a hollow object.
    // `proofs` gathers every per-purpose ProofEnvelope the parent minted
    // (top-level `proofs` map + any proof nested on a purpose block).
    const result: ConnectResult = {
      version: 1,
      anonymous: false,
      canonicalId: asString(payload['canonicalId']) ?? '',
      app: buildAppId(appBlock),
      proofs: collectProofs(payload, idBlock),
      connected: true,
      raw: payload,
    };

    // Core purposes: one data-driven loop over the purpose → id-field table.
    for (const [purpose, idField] of Object.entries(V1_PURPOSE_ID_FIELD)) {
      const block = buildPurpose(idBlock, purpose, idField);
      if (block) (result as Record<string, unknown>)[purpose] = block;
    }

    // UNKNOWN purposes (future platform additions / custom namespaces): pass
    // their `identities` entry through verbatim under its own key, so a new
    // purpose surfaces without an SDK release. Only real `identities` maps are
    // scanned (when the parent hoists blocks to the top level, `idBlock` IS the
    // payload and its non-purpose fields must not leak onto the result).
    if (isObject(identities)) {
      for (const [key, value] of Object.entries(identities)) {
        if (key === 'app' || key in V1_PURPOSE_ID_FIELD) continue; // already typed above
        if (!isObject(value)) continue; // a purpose entry is always an object
        (result as Record<string, unknown>)[key] = value;
      }
    }

    return result;
  }

  // ---- Anonymous: no identity shared. ----------------------------------------
  // Neither a V0 wallet nor a V1 identity block: the user is connected but shared
  // nothing. `canonicalId` is null and there is no session key (see sessionPubOf).
  return {
    anonymous: true,
    canonicalId: null,
    connected: true,
    raw: payload,
  };
}

/**
 * Select the session public key the codec verifies responses against.
 *
 * WHAT: V0 → `wallet.publicKeyHex`; V1 → `app.pub`; anonymous → `null`.
 * WHY:  every response after the connection is signed with EXACTLY this key. There
 *       is no fallback chain (per the "strict either-or" rule): the identity
 *       version selects one key, and an anonymous session legitimately has none
 *       (its responses carry no signature to verify, and `verifyResponse` treats a
 *       `null` key as "not established"). Returning the wrong key here would make
 *       every signature check fail — this selector is load-bearing.
 *
 * @param id the normalized identity.
 * @returns the hex public key, or `null` for anonymous / missing.
 */
export function sessionPubOf(id: NinjaIdentity): string | null {
  if (id.anonymous) return null;
  if (id.version === 0) return id.wallet.publicKeyHex || null;
  // version === 1
  return id.app.pub || null;
}

/**
 * Select the identity version the codec threads into `verifyResponse`.
 *
 * WHAT: V0 → `0`; V1 → `1`; anonymous → `undefined`.
 * WHY:  the version selects the verification curve/rules (both secp256k1 today,
 *       but the parameter exists so a future V1 curve change is a one-line edit in
 *       signature.ts). Anonymous has no established session, hence `undefined`.
 *
 * @param id the normalized identity.
 * @returns `0 | 1 | undefined`.
 */
export function sessionVersionOf(id: NinjaIdentity): 0 | 1 | undefined {
  if (id.anonymous) return undefined;
  return id.version;
}

/* ------------------------------------------------------------------ *
 * Internals — tiny, un-exported helpers keeping the module's public
 * surface to the three functions BUILD_SPEC pins.
 * ------------------------------------------------------------------ */

/** The V1 arm of the union, extracted so per-chain assignments stay type-checked. */
type ConnectResultV1 = Extract<ConnectResult, { version: 1 }>;

/** True iff `v` is a non-null, non-array object we can index safely. */
function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Return `v` when it is a string, else `undefined` — so callers can `??` a default. */
function asString(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

/** Read `block[key]` as an object, or `undefined` when absent/non-object. */
function pickBlock(block: Record<string, unknown>, key: string): Record<string, unknown> | undefined {
  const v = block[key];
  return isObject(v) ? v : undefined;
}

/**
 * Build the V1 `app` block (the session signing key + optional proof).
 *
 * WHAT: `{ pub, proof? }`. `pub` is the app-specific key every V1 response is
 *       verified against; `proof` is included only if the parent attached one.
 */
function buildAppId(appBlock: Record<string, unknown> | undefined): ConnectResultV1['app'] {
  const out: ConnectResultV1['app'] = { pub: asString(appBlock?.['pub']) ?? '' };
  const proof = asProof(appBlock?.['proof']);
  if (proof) out.proof = proof;
  return out;
}

/**
 * The declarative purpose → id-field table driving the V1 assembly loop.
 *
 * Each requestable core purpose maps to its chain-specific id-field name, or
 * `null` for a pure key purpose with no chain address (`content`). `app` is
 * deliberately absent — it is the session signer, built by {@link buildAppId}.
 * Adding a core purpose = one line here + the `IdentityV1` field in types.ts.
 */
const V1_PURPOSE_ID_FIELD: Record<ChainKind, string | null> = {
  bsv: 'address',
  icp: 'principal',
  kda: 'account',
  content: null,
};

/**
 * Build one per-purpose identity block (bsv/icp/kda/content) if the parent
 * shared it.
 *
 * WHAT: returns `{ [idField]?, pub, proof? }` for the purpose, or `undefined`
 *       when it wasn't shared. `idField` is the purpose's address-like key from
 *       {@link V1_PURPOSE_ID_FIELD} (`null` = pure key purpose, no id field).
 * WHY:  V1 identities are purpose-scoped; an app should be able to check
 *       `me.bsv` presence, so we only emit a block that actually exists rather
 *       than a hollow one with empty strings.
 */
function buildPurpose(
  idBlock: Record<string, unknown>,
  purpose: string,
  idField: string | null,
): Record<string, unknown> | undefined {
  const block = pickBlock(idBlock, purpose);
  if (!block) return undefined;
  const out: Record<string, unknown> = {
    ...(idField !== null ? { [idField]: asString(block[idField]) ?? '' } : {}),
    pub: asString(block['pub']) ?? '',
  };
  const proof = asProof(block['proof']);
  if (proof) out['proof'] = proof;
  return out;
}

/**
 * Collect every per-purpose ProofEnvelope the parent minted.
 *
 * WHAT: merges a top-level `proofs` map with any `proof` nested on a purpose
 *       block, keyed by {@link ProofPurpose}.
 * WHY:  proofs can arrive either as a dedicated `proofs: { app, bsv, ... }` map or
 *       inline on each identity block; gathering both here means the app reads one
 *       canonical `me.proofs` regardless of which layout the parent used. Both
 *       scans are data-driven off the payload's own keys (never a hardcoded
 *       purpose list), so proofs for future/custom purposes are collected too —
 *       `asProof` gates on the envelope scheme, filtering out non-proof fields.
 */
function collectProofs(
  payload: Record<string, unknown>,
  idBlock: Record<string, unknown>,
): Partial<Record<ProofPurpose, ProofEnvelope>> {
  const proofs: Partial<Record<ProofPurpose, ProofEnvelope>> = {};

  // Top-level `proofs` map wins as the explicit source — every key is honored,
  // including purposes the SDK doesn't know yet.
  const map = pickBlock(payload, 'proofs');
  if (map) {
    for (const p of Object.keys(map)) {
      const env = asProof(map[p]);
      if (env) proofs[p] = env;
    }
  }

  // Fill any gaps from a proof nested on the identity block's purpose entry.
  // (When the parent hoists blocks to the top level, `idBlock` is the payload
  // itself; the scheme gate in `asProof` keeps non-purpose fields out.)
  for (const p of Object.keys(idBlock)) {
    if (proofs[p]) continue;
    const env = asProof(pickBlock(idBlock, p)?.['proof']);
    if (env) proofs[p] = env;
  }

  return proofs;
}

/**
 * Structurally accept a value as a ProofEnvelope, or `undefined`.
 *
 * WHAT: returns the value typed as {@link ProofEnvelope} iff it is an object with
 *       the expected `scheme` and a `proof` object; else `undefined`.
 * WHY:  `.raw` keeps the untouched payload, so here we only need a light structural
 *       gate — client-side crypto verification is `ninja.identity.verifyProof`'s
 *       job, not the normalizer's.
 */
function asProof(v: unknown): ProofEnvelope | undefined {
  if (!isObject(v)) return undefined;
  if (v['scheme'] !== 'metanet-zk-identity-v1') return undefined;
  if (!isObject(v['proof'])) return undefined;
  return v as unknown as ProofEnvelope;
}
