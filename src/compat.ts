/**
 * shuriken-sdk — legacy compatibility layer (subpath `shuriken-sdk/compat`).
 *
 * WHAT: a drop-in replacement for the hand-copied `metanetSDK.js` files that the
 *       first-generation Metanet apps ship (scaffold, keepitreel, visualise_ai,
 *       nft_market, …). It exports a lazily-initializing `metanetSDK` singleton
 *       (default AND named) whose method names, signatures, resolved shapes,
 *       localStorage keys, and event semantics are IDENTICAL to the canonical
 *       scaffold copy — but every round trip runs on the new engine
 *       (`connect()` from `./index`: origin policy, correlation, per-command
 *       timeouts, signature verification).
 * WHY:  ~15 apps embed a bespoke `metanetSDK.js` today. Rewriting each of them
 *       onto the typed API is the right end state, but "swap one import line"
 *       (`import metanetSDK from 'shuriken-sdk/compat'`) gets every app onto the
 *       audited engine NOW — one place to fix bugs, verified signatures, no
 *       leaked listeners — while call sites migrate at their own pace.
 *
 * THE CONTRACT (strict): resolved-value field names match the legacy copy
 * byte-for-byte. `connect()` resolves the legacy `connectionData` object
 * (`appId, timestamp, anonymous, version, canonicalId, pubHex, rootPrincipal,
 * bsvAddress, bsvPublicKey, identities, wallets, icDelegation,
 * icDelegationPrivateKey, genericUseSeed, signature, appPageSchema, _raw`);
 * `payBSV`/`payICP`/history/swap/`createPost` resolve the raw wire payload;
 * `getFullTransaction` resolves `{ txid, rawHex, bumpHex }`; `getGeolocation`
 * resolves the flat location object; `scanQRCode` resolves `{ ref }`
 * immediately (fire-and-forget); listeners receive the ENTIRE wire envelope
 * (`responseData`), exactly like the legacy `_handlePlatformResponse` did.
 *
 * DOCUMENTED DIVERGENCES from the legacy copies (all deliberate):
 *  - Failures reject with a legacy-`message` `Error` that ADDITIONALLY carries
 *    `.code` (the `NinjaError` code) and `.ninjaError` for callers that want the
 *    typed taxonomy. Legacy rejected bare `Error(payload.error || '… failed')`.
 *  - Responses to promise-returning methods are signature-verified by the
 *    engine before they resolve (legacy singletons never verified). The
 *    listener mirror (`on`/`onGeolocation`/`onQRScanResponse`/…) is gated on
 *    source + origin like the engine but is NOT signature-verified — it is a
 *    read-only convenience channel, identical in trust level to the legacy
 *    listener it replaces; the promise APIs are the verified path.
 *  - `disconnect()` also removes `metanet_app_public_key` (the legacy copy
 *    wrote it on connect but forgot to clear it — an oversight, not a feature).
 *  - Standalone (non-iframe) use throws `NinjaError('ERR_NOT_EMBEDDED')`
 *    immediately instead of hanging into a 30s timeout.
 *
 * INIT BEHAVIOR: nothing happens at module load (the legacy copies attached a
 * global listener in the constructor; here construction is side-effect-free so
 * the module stays SSR-safe and tree-shakeable). On the FIRST method call the
 * layer (a) attaches the legacy event mirror, and (b) brings up the engine with
 * drop-in-safe defaults: `allowedOrigins` = the four production platform
 * origins, `dev` auto-detected from `location.hostname` (localhost/127.0.0.1).
 */

import { connect as createNinjaClient, type Ninja } from './index';
import { NinjaError, isNinjaError } from './errors';
import { makeOriginPolicy } from './transport/originPolicy';
import { newRef } from './protocol/correlation';
import { sha256Hex } from './protocol/signature';
import type {
  ChainKind,
  ConnectOptions,
  ConnectParams,
  ProofPurpose,
} from './types';

/* ------------------------------------------------------------------ *
 * Drop-in defaults.
 * ------------------------------------------------------------------ */

/**
 * The production platform origins a compat app accepts responses from.
 * WHY both apex and www: the legacy copies hardcoded only the `www.` hosts,
 * which silently broke apps embedded under the apex domains. The engine
 * normalizes origins, so listing all four is safe and strictly more correct.
 */
const COMPAT_ALLOWED_ORIGINS: readonly string[] = [
  'https://www.metanet.page',
  'https://metanet.page',
  'https://www.metanet.ninja',
  'https://metanet.ninja',
];

/**
 * The localStorage keys the legacy SDKs persisted on connect. Upstream app code
 * reads these keys DIRECTLY from localStorage (not through the SDK), so the
 * compat layer must keep writing the exact same names with the exact same values.
 */
const LS_PRIVATE_KEY = 'metanet_app_private_key'; // = genericUseSeed (hex)
const LS_PUBLIC_KEY = 'metanet_app_public_key'; // = SHA256(genericUseSeed) hex
const LS_BSV_ADDRESS = 'metanet_bsv_address'; // = wallet.address (V0 only)
const LS_PRINCIPAL = 'metanet_principal'; // = wallet.rootPrincipal (V0 only)

/**
 * Detect local development the way the task's drop-in contract specifies:
 * hostname is localhost or 127.0.0.1. WHY hostname (not `import.meta.env`):
 * the legacy copies keyed the origin bypass on the bundler's PROD flag, which
 * this package cannot see; the page's own hostname is bundler-agnostic and
 * matches how the engine's dev policy (loopback-only) is meant to be used.
 */
function detectDev(): boolean {
  if (typeof location === 'undefined') return false;
  const host = location.hostname;
  return host === 'localhost' || host === '127.0.0.1';
}

/**
 * localStorage, or null when unavailable (SSR, or a sandboxed iframe where
 * accessing it throws). The legacy copies crashed in those environments; the
 * compat layer degrades to "no persistence" — the resolved connectionData is
 * unaffected, only the convenience mirror keys are skipped.
 */
function safeLocalStorage(): Storage | null {
  try {
    return typeof localStorage !== 'undefined' ? localStorage : null;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ *
 * Legacy-facing types (the strict resolved-shape contract).
 * ------------------------------------------------------------------ */

/** `connect(options)` — the legacy V1 declaration block, passed through as-is. */
export interface LegacyConnectOptions {
  /** Navigation background color hint. */
  navbg?: string;
  /** V1: identities to request, keyed by purpose, each `{ proof?: boolean }`. */
  identities?: Partial<Record<ChainKind, { proof?: boolean }>>;
  /** V1: `{ proof?: boolean }` — the app identity itself always arrives. */
  appIdentity?: { proof?: boolean };
  /** V1: wallet-level info to request per chain. */
  wallets?: ChainKind[];
}

/**
 * The legacy `connectionData` object — field names are a STRICT contract
 * (upstream apps destructure these exact names). V0 responses populate the
 * wallet-derived fields; V1 responses populate `identities`/`wallets`; the
 * other family's fields are `undefined`/`null` exactly as in the legacy copy.
 */
export interface LegacyConnectionData {
  appId: unknown;
  timestamp: unknown;
  anonymous: boolean;
  version: number | null;
  canonicalId: string | null;
  /** The pub every response signature verifies against (V0 root / V1 app). */
  pubHex: string | null;
  // V0 legacy fields (undefined on V1)
  rootPrincipal: string | undefined;
  bsvAddress: string | undefined;
  bsvPublicKey: string | undefined;
  // V1 fields (null on V0)
  identities: Record<string, unknown> | null;
  wallets: unknown[] | null;
  icDelegation: unknown;
  icDelegationPrivateKey: unknown;
  genericUseSeed: string | undefined;
  signature: unknown;
  appPageSchema: unknown;
  /** The entire wire envelope (event.data), untouched — legacy debug hatch. */
  _raw: Record<string, unknown>;
}

/** Legacy BSV recipient shape (`value` in satoshis — NOT the typed API's `sats`). */
export interface LegacyBsvRecipient {
  address?: string;
  value: number;
  reason?: string;
  note?: string;
}

/** Legacy geolocation resolved shape (flat, field names pinned). */
export interface LegacyGeolocation {
  latitude: unknown;
  longitude: unknown;
  accuracy: unknown;
  altitude: unknown;
  heading: unknown;
  speed: unknown;
  timestamp: unknown;
}

/** A platform response envelope as legacy listeners received it (event.data). */
export type LegacyResponseData = Record<string, unknown>;

/** Legacy listener callback: receives the ENTIRE envelope, not just payload. */
export type LegacyListener = (responseData: LegacyResponseData) => void;

/**
 * Construction overrides — primarily for tests and unusual embeds. Apps should
 * use the exported singleton with zero configuration (that is the drop-in).
 */
export interface CompatOptions {
  /** Override the inbound origin allow-list (defaults to the platform origins). */
  allowedOrigins?: string[];
  /** Force dev (loopback-only) origin policy; default auto-detects localhost. */
  dev?: boolean;
  /** Engine handshake protocol preference (see ConnectOptions.protocols). */
  protocols?: number[];
  /** Ms to wait for `ninja-ready` before assuming a legacy parent. */
  readyTimeout?: number;
  /** Per-command timeout overrides (merged over the engine defaults). */
  timeoutMs?: ConnectOptions['timeoutMs'];
  /** Inject the parent window (tests); defaults to `window.parent`. */
  targetWindow?: Window;
}

/* ------------------------------------------------------------------ *
 * Error translation.
 * ------------------------------------------------------------------ */

/**
 * An Error carrying the legacy message plus the typed NinjaError metadata.
 * WHY both: legacy call sites string-match `err.message` ('Payment timeout',
 * payload.error, …), while migrated call sites want `err.code` for `t(code)`.
 */
export type LegacyError = Error & { code?: string; ninjaError?: NinjaError };

/**
 * Map an engine rejection onto the exact Error the legacy copy threw.
 *
 * WHAT: `ERR_TIMEOUT` → the method's legacy timeout message; a wire failure →
 *       `payload.error` when the parent sent one, else the method's legacy
 *       failure message. The NinjaError rides along on `.ninjaError`/`.code`.
 * WHY:  the legacy promise contract is `reject(new Error(payload.error ||
 *       '<method> failed'))` / `reject(new Error('<method> timeout'))`. Apps
 *       display `err.message` directly, so the compat layer must reproduce the
 *       strings — but we refuse to throw away the typed cause (that loss is
 *       exactly what the new error taxonomy exists to fix).
 */
function toLegacyError(e: unknown, failureMessage: string, timeoutMessage: string): LegacyError {
  if (isNinjaError(e)) {
    // The parent puts a human-ish reason in `payload.error` on failures; the
    // legacy copies surfaced exactly that string. (`asRecord` hoists.)
    const payloadRecord = asRecord(e.payload);
    const payloadError =
      payloadRecord && typeof payloadRecord['error'] === 'string'
        ? (payloadRecord['error'] as string)
        : undefined;
    const message =
      e.code === 'ERR_TIMEOUT' ? timeoutMessage : payloadError || failureMessage;
    const err = new Error(message) as LegacyError;
    err.code = e.code;
    err.ninjaError = e;
    return err;
  }
  return (e instanceof Error ? e : new Error(String(e))) as LegacyError;
}

/* ------------------------------------------------------------------ *
 * Tiny structural helpers (mirror the legacy's loose reads, typed safely).
 * ------------------------------------------------------------------ */

/** `v` as a plain object, else undefined — so payload reads can't throw. */
function asRecord(v: unknown): Record<string, unknown> | undefined {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : undefined;
}

/** `v` when it is a string, else undefined (for `??` chains à la legacy `?.`). */
function asString(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

/* ================================================================== *
 * The compat SDK class.
 * ================================================================== */

/**
 * `MetanetSDKCompat` — the legacy `MetanetSDK` class, re-implemented over the
 * engine. Exported so tests (and multi-frame edge cases) can construct isolated
 * instances with overrides; apps use the module-level singleton below.
 */
export class MetanetSDKCompat {
  /* ---- legacy public fields (some apps read these directly) ---------- */

  /**
   * Legacy parity: the scaffold dispatched every platform response as a
   * CustomEvent on this target (in addition to the callback registry). Kept so
   * an app doing `metanetSDK.eventTarget.addEventListener(...)` still works.
   */
  readonly eventTarget: EventTarget = new EventTarget();

  /**
   * Legacy parity: the callback registry, keyed by response `type`, values are
   * plain arrays (legacy used indexOf/splice removal — order-preserving,
   * duplicate-allowing). Public because the legacy field was.
   */
  readonly responseCallbacks = new Map<string, LegacyListener[]>();

  /** Legacy parity: flipped true by a resolved `connect()`, false by `disconnect()`. */
  isConnected = false;

  /** Legacy parity: the last resolved connectionData (null when disconnected). */
  connectionData: LegacyConnectionData | null = null;

  /**
   * Legacy parity: the origin allow-list (legacy called it `trustedOrigins`).
   * Informational — enforcement lives in the engine's origin policy and the
   * mirror's gate, both built from this same list.
   */
  readonly trustedOrigins: readonly string[];

  /* ---- internals ------------------------------------------------------ */

  /** Construction overrides (tests); empty for the drop-in singleton. */
  readonly #init: CompatOptions;

  /** Effective dev flag (explicit override, else hostname auto-detect). */
  readonly #dev: boolean;

  /** The memoized engine bring-up. Null until first use; cleared on failure. */
  #enginePromise: Promise<Ninja> | null = null;

  /** True once the legacy event mirror listener is attached to `window`. */
  #mirrorInstalled = false;

  /** The parent window we post fire-and-forget frames to (set by #touch). */
  #targetWindow: Window | null = null;

  /** The mirror's inbound-origin gate (same policy the engine uses). */
  #originAllowed: ((origin: string) => boolean) | null = null;

  /**
   * Captured `connection-response` envelopes, keyed by `payload.ref`.
   * WHY: the legacy `connectionData` includes envelope-top-level fields
   * (`signature`, `appPageSchema`, `genericUseSeed`, `icIdentityPackage`) and
   * `_raw` = the WHOLE envelope. The engine's `ninja.connect()` resolves the
   * normalized identity but not the raw envelope, so the mirror (which sees
   * every frame in the same dispatch tick, before the engine's promise
   * microtask runs) stashes it here for `connect()` to pick up by ref.
   * Bounded to a handful of entries so a hostile parent can't grow it.
   */
  readonly #connectionEnvelopes = new Map<string, LegacyResponseData>();

  /** `onCommand` listeners (SDKProvider-style wildcard listeners). */
  readonly #commandListeners = new Set<LegacyListener>();

  constructor(init: CompatOptions = {}) {
    // Side-effect-free by design: no window access, no listeners. Everything
    // real happens lazily in #touch()/#ensure() on the first method call, so
    // importing this module in SSR/tests costs nothing and breaks nothing.
    this.#init = init;
    this.#dev = init.dev ?? detectDev();
    this.trustedOrigins = init.allowedOrigins ?? [...COMPAT_ALLOWED_ORIGINS];
  }

  /* ------------------------------------------------------------------ *
   * Lazy initialization.
   * ------------------------------------------------------------------ */

  /**
   * #touch — the SYNCHRONOUS half of initialization: resolve the parent window
   * and attach the legacy event mirror. Idempotent; silently a no-op outside a
   * browser or outside an iframe (the ASYNC half, #ensure, is where "not
   * embedded" becomes a hard, typed error — mirrors need not throw because
   * events can only ever follow commands).
   */
  #touch(): void {
    if (this.#mirrorInstalled) return;
    if (typeof window === 'undefined') return; // SSR: nothing to attach to.

    const target = this.#init.targetWindow ?? window.parent;
    if (!target || target === (window as unknown)) return; // standalone: no parent.

    this.#targetWindow = target;

    // The mirror applies the SAME origin policy as the engine (built from the
    // same inputs) so the two inbound paths can never disagree about trust.
    this.#originAllowed = makeOriginPolicy({
      allowedOrigins: [...this.trustedOrigins],
      dev: this.#dev,
    });

    window.addEventListener('message', this.#mirrorHandler);
    this.#mirrorInstalled = true;
  }

  /**
   * The legacy event mirror — a faithful re-implementation of the legacy
   * `_handlePlatformResponse`, hardened with the engine's two inbound gates.
   *
   * WHAT: for every `message` event that (1) came from the parent window and
   *       (2) passed the origin policy and (3) carries the frozen
   *       `command: 'ninja-app-command'` marker, it: stashes connection
   *       envelopes for `connect()`; invokes every `responseCallbacks[type]`
   *       callback with the ENTIRE envelope; invokes every `onCommand`
   *       listener; and dispatches a CustomEvent on `eventTarget`.
   * WHY a second listener at all: the engine routes correlated responses to
   *       their pending promises and does NOT re-emit them, but the legacy
   *       contract is that `on('pay-response', cb)` fires for EVERY pay
   *       response — including ones another call site awaited. Only an
   *       independent mirror reproduces that. Callback faults are isolated
   *       (legacy let one throwing callback break the loop — a bug, not a
   *       behavior to preserve).
   */
  readonly #mirrorHandler = (event: MessageEvent): void => {
    // Gate 1: sender identity — same rule as the engine's Transport. A sibling
    // iframe cannot impersonate the parent even from an allowed origin.
    if (event.source !== this.#targetWindow) return;
    // Gate 2: origin allow-list / dev loopback.
    if (!this.#originAllowed || !this.#originAllowed(event.origin)) return;

    const data = asRecord(event.data);
    if (!data || data['command'] !== 'ninja-app-command') return;

    const type = asString(data['type']);

    // Stash connection envelopes for connect()'s legacy-shape assembly. Keyed
    // by payload.ref so concurrent connects can't cross wires; bounded so a
    // misbehaving parent can't grow the map unboundedly.
    if (type === 'connection-response') {
      const ref = asString(asRecord(data['payload'])?.['ref']);
      if (ref !== undefined) {
        this.#connectionEnvelopes.set(ref, data);
        if (this.#connectionEnvelopes.size > 8) {
          const oldest = this.#connectionEnvelopes.keys().next().value as string;
          this.#connectionEnvelopes.delete(oldest);
        }
      }
    }

    // Legacy callback registry: invoke with the entire envelope. Snapshot the
    // array so a callback that unsubscribes mid-dispatch (the `once` wrapper
    // does exactly that) can't skip its neighbors.
    if (type !== undefined) {
      const callbacks = this.responseCallbacks.get(type);
      if (callbacks) {
        for (const cb of [...callbacks]) {
          try {
            cb(data);
          } catch {
            /* isolate app-listener faults */
          }
        }
      }
    }

    // SDKProvider-style wildcard listeners (onCommand) see every platform frame.
    for (const listener of [...this.#commandListeners]) {
      try {
        listener(data);
      } catch {
        /* isolate */
      }
    }

    // Legacy parity: CustomEvent on the public eventTarget. Guarded because
    // CustomEvent is a browser/modern-node global.
    if (type !== undefined && typeof CustomEvent !== 'undefined') {
      try {
        this.eventTarget.dispatchEvent(new CustomEvent(type, { detail: data }));
      } catch {
        /* never let event plumbing break message handling */
      }
    }
  };

  /**
   * #ensure — the ASYNC half of initialization: bring up (and memoize) the
   * engine. Every promise-returning legacy method awaits this first.
   *
   * WHY memoized-with-clear-on-failure: concurrent first calls must share ONE
   * handshake (the engine owns the single transport), but a failed bring-up
   * (e.g. the app was mounted outside an iframe, then re-mounted inside one)
   * must not poison the singleton forever — clearing lets the next call retry.
   */
  #ensure(): Promise<Ninja> {
    if (this.#enginePromise) return this.#enginePromise;

    this.#touch();

    const opts: ConnectOptions = {
      allowedOrigins: [...this.trustedOrigins],
      dev: this.#dev,
      ...(this.#init.protocols !== undefined ? { protocols: this.#init.protocols } : {}),
      ...(this.#init.readyTimeout !== undefined ? { readyTimeout: this.#init.readyTimeout } : {}),
      ...(this.#init.timeoutMs !== undefined ? { timeoutMs: this.#init.timeoutMs } : {}),
      ...(this.#init.targetWindow !== undefined ? { targetWindow: this.#init.targetWindow } : {}),
    };

    this.#enginePromise = createNinjaClient(opts).catch((e: unknown) => {
      this.#enginePromise = null; // allow a later retry (see WHY above)
      throw e;
    });
    return this.#enginePromise;
  }

  /**
   * #postRaw — post a legacy-shaped fire-and-forget frame directly to the parent.
   *
   * WHAT: `parent.postMessage({ command: 'ninja-app-command', detail }, '*')` —
   *       byte-identical to the legacy `_sendCommand`.
   * WHY not `codec.call`: these commands (`write-clipboard`,
   *       `geolocation-stop`, `qr-scan-stop`, `qr-scan`) legitimately have no
   *       correlated response (or, for `qr-scan`, deliver responses to
   *       listeners, not a promise) — and the legacy contract requires
   *       `scanQRCode` to RETURN the ref it sent, which `codec.call` mints
   *       privately. Arming a response timer for a frame that never answers
   *       would be a phantom timeout; posting the raw frozen envelope is the
   *       honest shape. The envelope builder is trivial and the wire marker is
   *       the same frozen constant the engine uses.
   */
  #postRaw(detail: Record<string, unknown>): void {
    this.#touch();
    if (!this.#targetWindow) {
      throw new NinjaError('ERR_NOT_EMBEDDED', {
        hint: 'shuriken-sdk/compat must run inside a Metanet iframe; window.parent is missing or self.',
      });
    }
    this.#targetWindow.postMessage({ command: 'ninja-app-command', detail }, '*');
  }

  /* ------------------------------------------------------------------ *
   * CONNECTION & AUTHENTICATION
   * ------------------------------------------------------------------ */

  /**
   * connect — the legacy identity handshake. Resolves the legacy
   * `connectionData` object (see {@link LegacyConnectionData} — strict field
   * contract), stores it on `this.connectionData`, flips `isConnected`, and
   * persists the legacy localStorage keys.
   *
   * HOW it delegates: legacy options translate onto the engine's ergonomic
   * `ConnectParams` (`identities` keys → `request`, per-entry `proof` flags →
   * `proofs`, `appIdentity.proof` → `proofs: ['app']`, `wallets`/`navbg` pass
   * through) — the engine's `toConnectionWireParams` then produces the exact
   * same wire declaration block the legacy copy sent. Using `ninja.connect()`
   * (not a raw call) is load-bearing: it publishes the session verification
   * key into the codec, so every SUBSEQUENT compat call is signature-verified
   * — the one guarantee the legacy copies never had.
   *
   * The envelope-top-level extras (`genericUseSeed`, `signature`,
   * `appPageSchema`, `icIdentityPackage`) and `_raw` come from the mirror's
   * captured envelope (matched by the response's `ref`), because the engine's
   * normalized result intentionally doesn't carry the raw envelope.
   */
  async connect(options: LegacyConnectOptions = {}): Promise<LegacyConnectionData> {
    const ninja = await this.#ensure();

    // ---- Translate the legacy declaration block onto ConnectParams. ----
    const params: ConnectParams = {};
    const request: ChainKind[] = [];
    const proofs: ProofPurpose[] = [];
    const chains: ChainKind[] = ['bsv', 'icp', 'kda'];
    if (options.identities) {
      for (const chain of chains) {
        const entry = options.identities[chain];
        if (entry !== undefined) {
          request.push(chain); // presence of the key = "share this identity"
          if (entry && entry.proof) proofs.push(chain); // truthy proof flag = "mint its proof"
        }
      }
    }
    if (options.appIdentity && options.appIdentity.proof) proofs.push('app');
    if (request.length > 0) params.request = request;
    if (proofs.length > 0) params.proofs = proofs;
    // Legacy sent `navbg: options.navbg || null`; a null hint and an absent
    // hint are equivalent parent-side, so we only send a real value.
    if (options.navbg !== undefined && options.navbg !== null) params.navbg = options.navbg;
    if (options.wallets !== undefined && options.wallets.length > 0) {
      params.wallets = options.wallets;
    }

    // ---- Round trip through the engine (sets the session verify key). ----
    let raw: Record<string, unknown>;
    try {
      const result = await ninja.connect(params);
      raw = result.raw;
    } catch (e) {
      throw toLegacyError(e, 'Connection failed', 'Connection timeout - no response from platform');
    }

    // ---- Recover the full envelope the mirror captured for this response. ----
    // The mirror runs in the same synchronous message dispatch as the engine's
    // transport listener, and the engine's promise resolves in a LATER
    // microtask — so by the time we get here the envelope is always stashed.
    // A miss is therefore a logic bug that must surface, not be papered over.
    const ref = asString(raw['ref']);
    const envelope = ref !== undefined ? this.#connectionEnvelopes.get(ref) : undefined;
    if (ref !== undefined) this.#connectionEnvelopes.delete(ref);
    if (!envelope) {
      throw new NinjaError('ERR_UNKNOWN', {
        method: 'connection',
        hint: 'compat: connection-response envelope was not captured by the event mirror — this is a bug in shuriken-sdk/compat, please report it.',
      });
    }
    const payload = asRecord(envelope['payload']) ?? raw;

    // ---- Assemble the legacy connectionData (field-for-field). ----
    const wallet = asRecord(payload['wallet']);
    const identities = asRecord(payload['identities']) ?? null;
    const wallets = Array.isArray(payload['wallets']) ? (payload['wallets'] as unknown[]) : null;

    // V0 (legacy) wallet block — absent on V1 responses.
    const bsvAddress = wallet ? asString(wallet['address']) : undefined;
    const bsvPublicKey = wallet ? asString(wallet['publicKeyHex']) : undefined;
    const rootPrincipal = wallet ? asString(wallet['rootPrincipal']) : undefined;

    // Envelope-top-level extras (OUTSIDE the signed payload, per the protocol).
    const genericUseSeed = asString(envelope['genericUseSeed']);
    const icIdentityPackage = asRecord(envelope['icIdentityPackage']);

    this.connectionData = {
      appId: payload['appId'],
      timestamp: payload['timestamp'],
      anonymous: payload['anonymous'] === true, // legacy: `anonymous || false`
      // legacy: `payload?.version ?? (wallet ? 0 : null)`
      version:
        typeof payload['version'] === 'number' ? payload['version'] : wallet ? 0 : null,
      // Stable user key — present on both versions when logged in.
      canonicalId:
        asString(payload['canonicalId']) ??
        (identities ? asString(identities['canonicalId']) : undefined) ??
        (wallet ? asString(wallet['canonicalId']) : undefined) ??
        null,
      // The pub every response signature verifies against (V0 root / V1 app).
      pubHex: asString(payload['pubHex']) ?? bsvPublicKey ?? null,
      rootPrincipal,
      bsvAddress,
      bsvPublicKey,
      identities,
      wallets,
      icDelegation: payload['icDelegation'],
      icDelegationPrivateKey: icIdentityPackage?.['privateKey'],
      genericUseSeed,
      signature: envelope['signature'],
      appPageSchema: envelope['appPageSchema'],
      _raw: envelope,
    };
    this.isConnected = true;

    // ---- Legacy localStorage persistence (same keys, same derivations). ----
    // Upstream apps read these keys directly for their own API auth, so the
    // compat layer must keep them fresh. `metanet_app_public_key` is
    // SHA256(genericUseSeed) hex — byte-identical to the legacy
    // `CryptoJS.SHA256(seed).toString()` (both hash the UTF-8 hex STRING).
    const store = safeLocalStorage();
    if (store) {
      if (genericUseSeed !== undefined) {
        store.setItem(LS_PRIVATE_KEY, genericUseSeed);
        store.setItem(LS_PUBLIC_KEY, sha256Hex(genericUseSeed));
      }
      if (bsvAddress !== undefined) store.setItem(LS_BSV_ADDRESS, bsvAddress);
      if (rootPrincipal !== undefined) store.setItem(LS_PRINCIPAL, rootPrincipal);
    }

    return this.connectionData;
  }

  /** Legacy: `true` after a resolved `connect()`, until `disconnect()`. */
  isUserConnected(): boolean {
    return this.isConnected;
  }

  /** Legacy: the last resolved connectionData, or null. */
  getConnectionData(): LegacyConnectionData | null {
    return this.connectionData;
  }

  /**
   * Legacy: clear connection state + the persisted auth keys.
   * The engine stays up (the legacy listener also stayed attached) so a
   * subsequent `connect()` re-establishes identity over the same transport.
   * Divergence (documented in the header): also clears `metanet_app_public_key`,
   * which the legacy copy wrote but forgot to remove.
   */
  disconnect(): void {
    this.isConnected = false;
    this.connectionData = null;
    const store = safeLocalStorage();
    if (store) {
      store.removeItem(LS_PRIVATE_KEY);
      store.removeItem(LS_PUBLIC_KEY);
      store.removeItem(LS_BSV_ADDRESS);
      store.removeItem(LS_PRINCIPAL);
    }
  }

  /* ------------------------------------------------------------------ *
   * PAYMENTS
   * ------------------------------------------------------------------ */

  /**
   * payBSV — legacy BSV payment. `recipients` use the LEGACY field names
   * (`value` in satoshis, optional `reason`/`note`) and are sent verbatim —
   * byte-identical wire to the legacy copy (the parent accepts both the legacy
   * `value` and the typed API's `sats`). Resolves the raw wire payload
   * (`{ ref, success, ... }` + whatever the parent adds, e.g. the tx fields).
   *
   * NOTE (unchanged semantics): like the legacy copy, this does NOT broadcast —
   * the parent returns an authorized-but-unbroadcast raw tx. Migrate to
   * `ninja.pay.bsv(...)` for built-in network finalization.
   */
  async payBSV(recipients: LegacyBsvRecipient[]): Promise<LegacyResponseData> {
    const ninja = await this.#ensure();
    try {
      return await ninja.call<LegacyResponseData>('pay', { recipients });
    } catch (e) {
      throw toLegacyError(e, 'Payment failed', 'Payment timeout');
    }
  }

  /**
   * payICP — legacy ICP token payment. Positional args and the legacy nested
   * token spec (`token.specification.ledgerId`, recipient under `address`/
   * `value`/`note`) are preserved byte-for-byte on the wire.
   */
  async payICP(
    ledgerId: string,
    recipient: string,
    amount: number,
    memo = '',
  ): Promise<LegacyResponseData> {
    const ninja = await this.#ensure();
    try {
      return await ninja.call<LegacyResponseData>('pay', {
        token: { protocol: 'ICP', specification: { ledgerId } },
        recipients: [{ address: recipient, value: amount, note: memo }],
      });
    } catch (e) {
      throw toLegacyError(e, 'Payment failed', 'Payment timeout');
    }
  }

  /* ------------------------------------------------------------------ *
   * TOKEN OPERATIONS
   * ------------------------------------------------------------------ */

  /** getBSVHistory — legacy paginated BSV history; resolves the raw payload. */
  async getBSVHistory(
    options: { offset?: number; limit?: number } = {},
  ): Promise<LegacyResponseData> {
    const { offset = 0, limit = 50 } = options; // legacy defaults
    const ninja = await this.#ensure();
    try {
      return await ninja.call<LegacyResponseData>('token-history', { offset, limit });
    } catch (e) {
      throw toLegacyError(e, 'Failed to fetch BSV history', 'Request timeout');
    }
  }

  /** getICPTokenHistory — legacy ICP history via the nested index-canister spec. */
  async getICPTokenHistory(
    indexCanisterId: string,
    options: { offset?: number; limit?: number } = {},
  ): Promise<LegacyResponseData> {
    const { offset = 0, limit = 50 } = options;
    const ninja = await this.#ensure();
    try {
      return await ninja.call<LegacyResponseData>('token-history', {
        token: { protocol: 'ICP', specification: { indexCanisterId } },
        offset,
        limit,
      });
    } catch (e) {
      throw toLegacyError(e, 'Failed to fetch ICP token history', 'Request timeout');
    }
  }

  /**
   * getTokenHistory — DEPRECATED legacy method (kept because it's in the
   * canonical copy). Resolves `payload.history || payload.transactions || []`.
   * @deprecated Use getBSVHistory() or getICPTokenHistory() instead.
   */
  async getTokenHistory(tokenId: string, limit = 50): Promise<unknown[]> {
    // Same deprecation warning the legacy copy logged.
    console.warn(
      '[MetanetSDK] getTokenHistory() is deprecated. Use getBSVHistory() or getICPTokenHistory() instead.',
    );
    const ninja = await this.#ensure();
    let payload: LegacyResponseData;
    try {
      payload = await ninja.call<LegacyResponseData>('token-history', { tokenId, limit });
    } catch (e) {
      throw toLegacyError(e, 'Failed to fetch history', 'Request timeout');
    }
    // Legacy extraction order: history, then transactions, then empty array.
    const history = payload['history'];
    if (Array.isArray(history)) return history;
    const transactions = payload['transactions'];
    if (Array.isArray(transactions)) return transactions;
    return [];
  }

  /**
   * authorizeSwap — legacy swap authorization; `swapParams` spread into the
   * command exactly as the legacy copy did. Not in the engine's manifest, so it
   * goes through the uniform `call()` core with the legacy 60s deadline; the
   * behavior against any given parent is identical to the legacy copy's.
   */
  async authorizeSwap(swapParams: Record<string, unknown>): Promise<LegacyResponseData> {
    const ninja = await this.#ensure();
    try {
      return await ninja.call<LegacyResponseData>(
        'authorise-swap',
        { ...swapParams },
        { timeoutMs: 60_000 }, // legacy deadline (engine default would be 30s)
      );
    } catch (e) {
      throw toLegacyError(e, 'Swap authorization failed', 'Swap authorization timeout');
    }
  }

  /** swapBuy — legacy swap purchase; same passthrough pattern as authorizeSwap. */
  async swapBuy(buyParams: Record<string, unknown>): Promise<LegacyResponseData> {
    const ninja = await this.#ensure();
    try {
      return await ninja.call<LegacyResponseData>(
        'swap-buy',
        { ...buyParams },
        { timeoutMs: 60_000 }, // legacy deadline
      );
    } catch (e) {
      throw toLegacyError(e, 'Swap buy failed', 'Swap buy timeout');
    }
  }

  /* ------------------------------------------------------------------ *
   * TRANSACTIONS
   * ------------------------------------------------------------------ */

  /**
   * getFullTransaction — legacy SPV fetch. Maps the parent's snake_case wire
   * fields to the legacy resolved names: `tx_hex` → `rawHex`, `bump_hex` →
   * `bumpHex` (field names pinned by the legacy contract).
   */
  async getFullTransaction(
    txid: string,
  ): Promise<{ txid: string; rawHex: string; bumpHex: string }> {
    const ninja = await this.#ensure();
    let payload: LegacyResponseData;
    try {
      payload = await ninja.call<LegacyResponseData>('full-transaction', { txid });
    } catch (e) {
      throw toLegacyError(e, 'Failed to fetch transaction', 'Transaction fetch timeout');
    }
    return {
      txid: payload['txid'] as string,
      rawHex: payload['tx_hex'] as string,
      bumpHex: payload['bump_hex'] as string,
    };
  }

  /* ------------------------------------------------------------------ *
   * GEOLOCATION
   * ------------------------------------------------------------------ */

  /**
   * getGeolocation — legacy one-shot/first-fix location. Sends the legacy
   * `{ watch, highAccuracy }` params (defaults false/false) and resolves the
   * flat legacy location object off the FIRST frame. With `watch: true`,
   * subsequent frames flow to `onGeolocation` listeners (via the mirror),
   * exactly as before; the promise still settles on the first fix.
   */
  async getGeolocation(
    options: { watch?: boolean; highAccuracy?: boolean } = {},
  ): Promise<LegacyGeolocation> {
    const ninja = await this.#ensure();
    let payload: LegacyResponseData;
    try {
      payload = await ninja.call<LegacyResponseData>('geolocation', {
        watch: options.watch || false,
        highAccuracy: options.highAccuracy || false,
      });
    } catch (e) {
      throw toLegacyError(e, 'Geolocation failed', 'Geolocation timeout');
    }
    // The legacy resolved shape: flat fields, passed through untouched.
    return {
      latitude: payload['latitude'],
      longitude: payload['longitude'],
      accuracy: payload['accuracy'],
      altitude: payload['altitude'],
      heading: payload['heading'],
      speed: payload['speed'],
      timestamp: payload['timestamp'],
    };
  }

  /**
   * stopGeolocation — legacy fire-and-forget stop (no ref, no response).
   * Posted as the raw legacy frame; the parent stops the platform-side watch.
   */
  stopGeolocation(): void {
    this.#postRaw({ type: 'geolocation-stop' });
  }

  /**
   * onGeolocation — legacy continuous-updates listener. The callback receives
   * each frame's PAYLOAD (legacy destructured `{ payload }` and forwarded it).
   * @returns cleanup function that unsubscribes.
   */
  onGeolocation(callback: (payload: LegacyResponseData) => void): () => void {
    const handler: LegacyListener = (responseData) => {
      const payload = asRecord(responseData['payload']);
      if (payload) callback(payload); // legacy: `if (payload) callback(payload)`
    };
    this.on('geolocation-response', handler);
    return () => {
      this.off('geolocation-response', handler);
    };
  }

  /* ------------------------------------------------------------------ *
   * QR SCANNING
   * ------------------------------------------------------------------ */

  /**
   * scanQRCode — legacy fire-and-forget scanner open. Returns `{ ref }`
   * IMMEDIATELY (it is NOT a result promise); scan results arrive via
   * `onQRScanResponse`, scanner-closed via `onQRScanStop` — the legacy
   * listener pattern, served by the mirror. The ref is minted here (not by the
   * codec) precisely because the legacy contract hands it back to the caller
   * for matching `payload.ref` in the listeners.
   */
  async scanQRCode(options: Record<string, unknown> = {}): Promise<{ ref: string }> {
    const ref = newRef();
    this.#postRaw({ type: 'qr-scan', ref, ...options });
    return { ref };
  }

  /** onQRScanResponse — per-scan-result listener; callback receives the payload. */
  onQRScanResponse(callback: (payload: LegacyResponseData) => void): () => void {
    const handler: LegacyListener = (responseData) => {
      callback(asRecord(responseData['payload']) ?? {});
    };
    this.on('qr-scan-response', handler);
    return () => {
      this.off('qr-scan-response', handler);
    };
  }

  /** onQRScanStop — fires when the user closes the scanner; receives the payload. */
  onQRScanStop(callback: (payload: LegacyResponseData) => void): () => void {
    const handler: LegacyListener = (responseData) => {
      callback(asRecord(responseData['payload']) ?? {});
    };
    this.on('qr-scan-stop-response', handler);
    return () => {
      this.off('qr-scan-stop-response', handler);
    };
  }

  /** stopQRScan — legacy fire-and-forget scanner close (no ref, no response). */
  stopQRScan(): void {
    this.#postRaw({ type: 'qr-scan-stop' });
  }

  /* ------------------------------------------------------------------ *
   * CONTENT CREATION
   * ------------------------------------------------------------------ */

  /** createPost — legacy feed post; `postData` spread verbatim, payload resolved. */
  async createPost(postData: Record<string, unknown>): Promise<LegacyResponseData> {
    const ninja = await this.#ensure();
    try {
      return await ninja.call<LegacyResponseData>('create-post', { ...postData });
    } catch (e) {
      throw toLegacyError(e, 'Post creation failed', 'Create post timeout');
    }
  }

  /* ------------------------------------------------------------------ *
   * UTILITIES
   * ------------------------------------------------------------------ */

  /**
   * openLink — legacy consent-gated navigation. Resolves `payload.success`
   * (a BOOLEAN — the legacy copy resolved even a declined `false`, it only
   * REJECTED on timeout). The engine turns a `success: false` payload into a
   * rejection, so we translate that specific case back into `false` here.
   */
  async openLink(url: string): Promise<boolean> {
    const ninja = await this.#ensure();
    try {
      const payload = await ninja.call<LegacyResponseData>('open-link', { url }, {
        timeoutMs: 10_000, // legacy deadline (matches the engine default too)
      });
      return payload['success'] === true;
    } catch (e) {
      // A declined/failed open resolved `false` in the legacy copy; only the
      // timeout (and non-wire client faults) rejected.
      if (isNinjaError(e) && e.payload) return false;
      throw toLegacyError(e, 'Open link timeout', 'Open link timeout');
    }
  }

  /** writeClipboard — legacy fire-and-forget clipboard write (no ref, no response). */
  writeClipboard(text: string): void {
    this.#postRaw({ type: 'write-clipboard', text });
  }

  /* ------------------------------------------------------------------ *
   * EVENT HANDLING (legacy pub/sub — Map registry, array values)
   * ------------------------------------------------------------------ */

  /**
   * on — register `callback` for a platform response `eventType` (e.g.
   * 'pay-response'). The callback receives the ENTIRE wire envelope. Multiple
   * callbacks per event; duplicates allowed — legacy semantics exactly.
   */
  on(eventType: string, callback: LegacyListener): void {
    this.#touch(); // make sure the mirror is listening before events can matter
    let callbacks = this.responseCallbacks.get(eventType);
    if (!callbacks) {
      callbacks = [];
      this.responseCallbacks.set(eventType, callbacks);
    }
    callbacks.push(callback);
  }

  /** off — remove `callback` by reference (indexOf/splice; no-op if absent). */
  off(eventType: string, callback: LegacyListener): void {
    const callbacks = this.responseCallbacks.get(eventType);
    if (!callbacks) return;
    const index = callbacks.indexOf(callback);
    if (index > -1) callbacks.splice(index, 1);
  }

  /** once — fire exactly once, then self-remove (legacy wrapper pattern). */
  once(eventType: string, callback: LegacyListener): void {
    const wrappedCallback: LegacyListener = (responseData) => {
      this.off(eventType, wrappedCallback);
      callback(responseData);
    };
    this.on(eventType, wrappedCallback);
  }

  /* ------------------------------------------------------------------ *
   * DRIFTED-COPY EXTRAS — SDKProvider-style helpers (nft_market, we_ask_ai)
   * ------------------------------------------------------------------ */

  /**
   * sendCommand — SDKProvider drift: post an arbitrary command object to the
   * parent with no ref tracking. Supportable (it is exactly the raw envelope),
   * so it is implemented — but prefer `ninja.call(...)` on the typed SDK,
   * which correlates and verifies the reply.
   */
  sendCommand(commandObj: Record<string, unknown>): void {
    this.#postRaw(commandObj);
  }

  /**
   * onCommand — SDKProvider drift: a wildcard listener over every inbound
   * platform frame (the SDKProvider used it to drive its own routing).
   * The listener receives the entire envelope. NOTE: the SDKProvider verified
   * secp256k1 signatures per message inside onCommand; here verification lives
   * in the engine for all promise APIs, and this mirror channel is gated on
   * source + origin only — same trust level as the legacy singleton listener.
   */
  onCommand(listener: LegacyListener): void {
    this.#touch();
    this.#commandListeners.add(listener);
  }

  /** offCommand — remove a wildcard listener registered via onCommand. */
  offCommand(listener: LegacyListener): void {
    this.#commandListeners.delete(listener);
  }

  /* ------------------------------------------------------------------ *
   * DRIFTED-COPY EXTRAS — unsupportable inventions (throw, with a hint)
   *
   * keepitreel / visualise_ai grew a camera + video-transcode bridge, and the
   * SDKProviders an ICP `authUser`, none of which exist in the platform's
   * frozen command set (manifest.json is the source of truth: there is no
   * `camera`, `video-transcode`, or auth command). Stubbing them to throw a
   * precise, typed `ERR_NOT_SUPPORTED` — instead of omitting them — turns a
   * confusing `undefined is not a function` into an actionable error.
   * ------------------------------------------------------------------ */

  /** @throws ERR_NOT_SUPPORTED — `camera` was never a platform command. */
  requestCamera(_options: Record<string, unknown> = {}): never {
    throw new NinjaError('ERR_NOT_SUPPORTED', {
      method: 'camera',
      hint: 'The camera bridge was an app-local experiment, not a platform command. Use navigator.mediaDevices.getUserMedia in your app, or ninja.qr.scan for QR capture.',
    });
  }

  /** @throws ERR_NOT_SUPPORTED — see requestCamera. */
  onCameraFrame(_callback: (payload: unknown) => void): never {
    throw new NinjaError('ERR_NOT_SUPPORTED', {
      method: 'camera',
      hint: 'camera-stream-frame events do not exist on the platform. Use getUserMedia in your app.',
    });
  }

  /** @throws ERR_NOT_SUPPORTED — see requestCamera. */
  captureFrame(_ref: string): never {
    throw new NinjaError('ERR_NOT_SUPPORTED', {
      method: 'camera-capture',
      hint: 'camera-capture was never a platform command. Capture from your own getUserMedia stream.',
    });
  }

  /** @throws ERR_NOT_SUPPORTED — see requestCamera. */
  stopCamera(_ref: string): never {
    throw new NinjaError('ERR_NOT_SUPPORTED', {
      method: 'camera-stop',
      hint: 'camera-stop was never a platform command.',
    });
  }

  /** @throws ERR_NOT_SUPPORTED — `video-transcode` was never a platform command. */
  transcodeVideo(_videoFile: unknown, _options: Record<string, unknown> = {}): never {
    throw new NinjaError('ERR_NOT_SUPPORTED', {
      method: 'video-transcode',
      hint: 'video-transcode was an app-local experiment. Transcode client-side (e.g. ffmpeg.wasm) or server-side before upload.',
    });
  }

  /** @throws ERR_NOT_SUPPORTED — see transcodeVideo. */
  onTranscodeProgress(_callback: (payload: unknown) => void): never {
    throw new NinjaError('ERR_NOT_SUPPORTED', {
      method: 'video-transcode',
      hint: 'video-transcode-progress events do not exist on the platform.',
    });
  }

  /**
   * @throws ERR_NOT_SUPPORTED — `authUser` was SDKProvider-local: it drove an
   * app-specific ICP canister (`agent.whoami` / `auth_user`) with app state the
   * SDK cannot own. Build it in your app on top of `connectionData.icDelegation`
   * / the `icIdentityPackage` from `connect()`.
   */
  authUser(): never {
    throw new NinjaError('ERR_NOT_SUPPORTED', {
      method: 'connection',
      hint: 'authUser was app-specific (an ICP canister call), not an SDK method. Use connect()’s icDelegation/icIdentityPackage to build your agent in-app.',
    });
  }
}

/* ================================================================== *
 * The drop-in singleton.
 *
 * WHY module-level (like the legacy copies): every hand-rolled metanetSDK.js
 * exported a singleton instance as its default export, and apps import it from
 * dozens of files expecting shared state (isConnected, connectionData, the
 * listener registry). Construction is side-effect-free (see the constructor),
 * so this is safe at import time in any environment.
 * ================================================================== */

/** The drop-in legacy singleton: `import metanetSDK from 'shuriken-sdk/compat'`. */
const metanetSDK = new MetanetSDKCompat();

export default metanetSDK;
export { metanetSDK };

/** Legacy named-class parity: the scaffold exported `{ MetanetSDK }` too. */
export { MetanetSDKCompat as MetanetSDK };
