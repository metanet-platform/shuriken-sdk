/**
 * shuriken-sdk — public entry point.
 *
 * WHAT: the single module a host app imports. `connect(options)` performs the
 *       whole bring-up dance (origin policy -> transport -> handshake -> codec ->
 *       session store) and returns a fully assembled `Ninja` facade whose methods
 *       are the typed sugar every module contributes.
 * WHY:  the ~15 hand-copied SDKs each re-derived this wiring slightly differently,
 *       so no two agreed on origin checks, timeouts, or signature verification.
 *       Centralizing the assembly here — over the frozen wire protocol in
 *       PROTOCOL.md and the machine-readable `manifest.json` — is what makes the
 *       SDK cohesive and impossible to mis-wire. Every construction step is a
 *       named module (see BUILD_SPEC.md); this file only orchestrates them.
 *
 * Re-exports at the bottom make the package's whole public type contract, the
 * error class + narrowing guard, and the ledger token table available from the
 * one import path callers already use.
 */

import type {
  CallOptions,
  ConnectOptions,
  ConnectParams,
  ConnectResult,
  Negotiated,
  NinjaEvents,
  NinjaMethod,
  ResponsePayload,
} from './types';
import { NinjaError } from './errors';

// ── Construction primitives (each its own audited module; see BUILD_SPEC) ──────
import { makeOriginPolicy } from './transport/originPolicy';
import { Transport } from './transport/transport';
import { negotiate } from './transport/handshake';
import { Codec, type Session } from './protocol/codec';

// ── Typed sugar factories (thin wrappers over codec.call / codec.stream) ───────
import { makeConnect } from './commands/connect';
import { makePay } from './commands/pay';
import { makeFeed } from './commands/feed';
import { makeTx } from './commands/tx';
import { makeProof } from './commands/proof';
import { makeGeo } from './commands/geo';
import { makeQr } from './commands/qr';
import { makeUtil } from './commands/util';
import { makeIdentity } from './commands/identity';
import { tokens } from './tokens';

// The bundled machine-readable contract. `resolveJsonModule` is on, and this file
// is published alongside `dist/` (see package.json `exports["./manifest.json"]`),
// so `capabilities(method)` can hand callers the authoritative per-command slice
// (schema, consent overlay, errors, examples) at runtime — never a stale copy.
import manifest from '../manifest.json';

/* ------------------------------------------------------------------ *
 * Defaults — timeouts come straight from PROTOCOL.md so the docs, the
 * runtime, and the manifest stay in lockstep. A per-command entry wins
 * over `default`; anything omitted here falls back to `default`.
 * ------------------------------------------------------------------ */

/**
 * Per-command deadlines in milliseconds (PROTOCOL.md "Timeouts").
 *
 * DESIGN RULE: a deadline exists to catch a DEAD/unresponsive parent — never to
 * race the USER. Consent-gated, user-paced flows (`pay`, `create-post`,
 * `generate-proof`, consent-bearing `connection`, `open-link`) keep the request
 * pending while the user reads/fills a platform overlay (and first-time Groth16
 * proving can take minutes on top), so they get a LONG deadline (10 min / 2 min)
 * instead of 30–60s — a 30s timer fired mid-form, rejecting requests that then
 * SUCCEEDED parent-side. Pure data reads stay snappy (30s). `default` catches
 * any future method. Every value is overridable via connect({ timeoutMs }) or
 * per-call opts.
 */
const DEFAULT_TIMEOUTS: Record<string, number> = {
  default: 30_000,
  'open-link': 120_000,       // consent overlay — user decides at their own pace
  'full-transaction': 30_000, // data read
  'token-history': 30_000,    // data read
  geolocation: 30_000,        // streams don't arm call timers; kept for parity
  connection: 30_000,         // bare connect; consent-bearing connects escalate to 10 min (connect.ts)
  pay: 600_000,               // user fills/confirms the payment form
  'create-post': 600_000,     // user completes the whole post form
  'generate-proof': 600_000,  // consent + first-time proving (zkey download + Groth16)
};

/**
 * Handshake protocol preference (highest first). Default `[1, 0]` prefers the
 * negotiation-aware V1 parent but cleanly falls back to the frozen V0 wire.
 * A frozen app can pin `[0]` and keep working indefinitely (PROTOCOL.md §3).
 */
const DEFAULT_PROTOCOLS = [1, 0];

/** How long to wait for `ninja-ready` before assuming a legacy parent (PROTOCOL.md). */
const DEFAULT_READY_TIMEOUT = 1_500;

/**
 * The full command set advertised to a legacy parent that never answers the
 * handshake. WHY: today's live parent ignores `ninja-hello`, so on the
 * assume-legacy path we must advertise every real command or the app would
 * think a live capability is missing. Sourced from the manifest so it can never
 * drift from the actual handler set.
 */
const LEGACY_CAPABILITIES: string[] = Object.keys(manifest.commands);

/** Our own package version, sent in `ninja-hello` so parents can log/branch on it. */
const SDK_VERSION = '0.1.0'; // TODO(v1.0): import from package.json version at build time.

/* ------------------------------------------------------------------ *
 * A minimal, dependency-free typed event emitter.
 *
 * WHY hand-rolled: the SDK must stay at zero runtime deps beyond @noble/*, and
 * the surface we need is tiny — `on`, `off`, and an internal `emit`. Listener
 * errors are swallowed (a bad app handler must never corrupt SDK state or block
 * sibling listeners). This backs `ninja.on(...)`, which the codec's `onEvent`
 * feeds with any unrecognized `<type>-response` frame (PROTOCOL.md forward-compat
 * rule 2: unknown responses are routed, never dropped).
 * ------------------------------------------------------------------ */

type AnyListener = (...args: any[]) => void;

class Emitter {
  /** event name -> set of listeners. A Set gives idempotent add + O(1) remove. */
  private readonly map = new Map<string, Set<AnyListener>>();

  /** Register `fn` for `event`. Returns nothing; pair with `off` to remove. */
  on(event: string, fn: AnyListener): void {
    let set = this.map.get(event);
    if (!set) {
      set = new Set();
      this.map.set(event, set);
    }
    set.add(fn);
  }

  /** Remove `fn` from `event` (no-op if it was never registered). */
  off(event: string, fn: AnyListener): void {
    this.map.get(event)?.delete(fn);
  }

  /**
   * Fan a payload out to every listener of `event`. Errors thrown by an app
   * listener are isolated so one bad handler can neither break the SDK nor
   * starve the other listeners.
   */
  emit(event: string, ...args: any[]): void {
    const set = this.map.get(event);
    if (!set) return;
    // Copy to a snapshot so a listener that unsubscribes mid-dispatch is safe.
    for (const fn of [...set]) {
      try {
        fn(...args);
      } catch {
        /* isolate app-listener faults — never propagate into SDK internals */
      }
    }
  }

  /** Drop every listener (called on `disconnect`, so a torn-down client is inert). */
  clear(): void {
    this.map.clear();
  }
}

/* ------------------------------------------------------------------ *
 * The public Ninja facade type.
 * ------------------------------------------------------------------ */

/**
 * `Ninja` — the object `connect()` resolves to and the whole app-facing API.
 *
 * WHAT: a uniform low-level `call`/event core, plus the typed sugar namespaces
 *       generated over it (`pay`, `feed`, `tx`, `proof`, `geo`, `qr`, …), plus
 *       introspection (`negotiated`, `protocol`, `capabilities`) and teardown.
 * WHY:  one flat, discoverable surface means callers never reach for the wire
 *       envelope directly; every method is typed by `manifest.json`.
 */
export interface Ninja {
  /**
   * The uniform escape hatch: send any manifest command and await its typed
   * result. All sugar below is a thin wrapper over this. Rejects with a
   * `NinjaError` whose `.code` is localizable.
   */
  call<T = any>(method: NinjaMethod | string, params?: object, opts?: CallOptions): Promise<T>;

  /** Subscribe to an SDK event (e.g. `disconnect`, or any unrouted `<type>-response`). */
  on<K extends keyof NinjaEvents>(event: K, fn: NinjaEvents[K]): void;
  on(event: string, fn: (...args: any[]) => void): void;

  /** Remove a previously registered listener. */
  off<K extends keyof NinjaEvents>(event: K, fn: NinjaEvents[K]): void;
  off(event: string, fn: (...args: any[]) => void): void;

  /**
   * Re-run the connection handshake (share more chains / mint more proofs) and
   * atomically re-point the session key used for signature verification. This is
   * `makeConnect`, closed over the live codec + session setter.
   */
  connect(params?: ConnectParams): Promise<ConnectResult>;

  /** Payment sugar: `pay.bsv(...)`, `pay.icp(...)`, `pay.kda(...)`. */
  pay: ReturnType<typeof makePay>;
  /** Social feed sugar: `feed.createPost(...)`. */
  feed: ReturnType<typeof makeFeed>;
  /** Transaction sugar: `tx.get(...)`, `tx.history(...)`. */
  tx: ReturnType<typeof makeTx>;
  /** ZK identity-proof sugar: `proof.generate(...)`. */
  proof: ReturnType<typeof makeProof>;
  /** Geolocation sugar (streaming): `geo.current()`, `geo.watch()`. */
  geo: ReturnType<typeof makeGeo>;
  /** QR-scanner sugar (streaming): `qr.scan(onResult)`. */
  qr: ReturnType<typeof makeQr>;

  /** Clipboard helper (write-only, as the parent only exposes write). */
  clipboard: ReturnType<typeof makeUtil>['clipboard'];
  /** Ask the parent to open an external link. */
  openLink: ReturnType<typeof makeUtil>['openLink'];

  /**
   * Client-side ZK proof verification (real Groth16 pairing check against the
   * embedded SHA-pinned vkeys): `identity.verifyProof(env, canonicalId, pub)`
   * → boolean, `identity.verifyProofOrThrow(...)` → throws ERR_PROOF_INVALID.
   * Also `identity.decodeCanonicalId(me.canonicalId)` →
   * `{ version, anchorHex, seedCommitment? }` — reads BOTH V0 and V1 anchors
   * from the one self-describing canonicalId string (pure decode, no ZK check).
   */
  identity: ReturnType<typeof makeIdentity>;

  /**
   * Named ICP ledger aliases (`ninja.tokens.ckUSDC` -> canister id), so payment
   * code never hardcodes a canister id. Same object as the top-level `tokens`
   * export; attached here for discoverability off the client.
   */
  readonly tokens: typeof tokens;

  /** The negotiated protocol number (0 for the assume-legacy path). */
  readonly protocol: number;
  /** The full result of the handshake (protocol, capability set, ledgers). */
  readonly negotiated: Negotiated;

  /**
   * Introspect capabilities.
   * - `capabilities()` -> the manifest slice for every negotiated command.
   * - `capabilities(method)` -> the manifest slice for one command (or `undefined`
   *   if that method wasn't negotiated / doesn't exist).
   */
  capabilities(): Record<string, unknown>;
  capabilities(method: string): Record<string, unknown> | undefined;

  /** Tear down the transport, reject all in-flight calls, and go inert. */
  disconnect(): void;
}

/* ------------------------------------------------------------------ *
 * connect() — the assembly.
 * ------------------------------------------------------------------ */

/**
 * Bring up a `Ninja` client against the embedding parent window.
 *
 * WHAT (in order):
 *   1. Resolve the target window (defaults to `window.parent`). Standalone apps
 *      (no parent, or `parent === self`) fail fast with `ERR_NOT_EMBEDDED` — the
 *      SDK is meaningless outside an iframe and must say so, not hang.
 *   2. Build the inbound origin policy (prod: allow-list; `dev:true`: localhost).
 *   3. Wrap the window in a `Transport` (postMessage out, filtered listen in).
 *   4. Run the `ninja-hello`/`ninja-ready` handshake, or assume-legacy on timeout.
 *   5. Stand up the `Codec` (the request/stream engine) with a *mutable* session
 *      cell it reads on every response for signature verification, and an
 *      `onEvent` that forwards unrouted frames to the emitter.
 *   6. Assemble and return the flat `Ninja` facade.
 *
 * WHY a mutable session cell: the verification key is not known until the first
 * `connect()` reply, and it *changes* when the app re-connects (V0 root key ->
 * V1 app key, or a re-key with a new salt). The codec must always verify against
 * the *current* key, so it reads a live `getSession()` rather than a snapshot —
 * `makeConnect` calls `setSession(...)` the instant a new identity is normalized.
 */
export async function connect(options: ConnectOptions = {}): Promise<Ninja> {
  // 1. Resolve + guard the target window. --------------------------------------
  //    `targetWindow` injection exists purely so tests (and unusual embeds) can
  //    supply a stub; production apps let it default to `window.parent`.
  const targetWindow =
    options.targetWindow ??
    (typeof window !== 'undefined' ? window.parent : undefined);

  if (!targetWindow || (typeof window !== 'undefined' && targetWindow === window)) {
    // No parent frame (opened standalone, or SSR with no `window`): there is
    // nobody to talk to. Surface it as a typed, catchable client error.
    throw new NinjaError('ERR_NOT_EMBEDDED', {
      method: 'connection',
      hint: 'shuriken-sdk must run inside a Metanet iframe; window.parent is missing or self.',
    });
  }

  // 2. Origin policy. `makeOriginPolicy` throws at construction on the classic
  //    misconfig (no allowedOrigins and not dev), so a foot-gun surfaces here at
  //    connect time rather than as a silent "no responses ever arrive".
  const isAllowedOrigin = makeOriginPolicy({
    ...(options.allowedOrigins !== undefined ? { allowedOrigins: options.allowedOrigins } : {}),
    ...(options.dev !== undefined ? { dev: options.dev } : {}),
  });

  // 3. Transport: the only thing that touches `postMessage` and the origin gate.
  const transport = new Transport(targetWindow, isAllowedOrigin);

  // 4. Handshake. Resolves to a real `ninja-ready` payload or the assume-legacy
  //    default (protocol 0, full command set) after `readyTimeout` — it never
  //    rejects, so a frozen/legacy parent still yields a usable client.
  const negotiated: Negotiated = await negotiate(transport, {
    protocols: options.protocols ?? DEFAULT_PROTOCOLS,
    readyTimeout: options.readyTimeout ?? DEFAULT_READY_TIMEOUT,
    capabilitiesFallback: LEGACY_CAPABILITIES,
  });

  // 5a. The mutable session cell. Starts empty: the *connection* response is the
  //     one payload signed by a key we don't yet hold, so `verifyResponse` treats
  //     a `null` pub as "not-yet-established" and lets it through on the origin
  //     check alone (documented in signature.ts). Every later call verifies
  //     against whatever `makeConnect` has since stored here.
  let session: Session = { pub: null, version: undefined, genericUseSeed: null };
  const getSession = (): Session => session;
  const setSession = (s: Session): void => {
    session = s;
  };

  // 5b. The event emitter backing `ninja.on/off`, and the codec's `onEvent` sink.
  const emitter = new Emitter();

  // 5c. Merge caller timeout overrides on top of the protocol defaults. A partial
  //     override table only replaces the keys it names; everything else keeps the
  //     documented default. `default` is always present.
  const timeouts: Record<string, number> = { ...DEFAULT_TIMEOUTS, ...(options.timeoutMs ?? {}) };
  // DEFAULT_TIMEOUTS.default is a literal constant (30_000), always present, but
  // `noUncheckedIndexedAccess` types a string-index read as `number | undefined`.
  // Fall back to the hard-coded floor so `defaultTimeout` is a definite number.
  const defaultTimeout: number = timeouts['default'] ?? 30_000;

  // 5d. The engine. `onEvent` is where the codec sends any inbound `<type>-response`
  //     that matched no pending call and no active stream — forward-compat rule 2:
  //     surface it on `ninja.on(type)` instead of dropping it.
  const codec = new Codec(transport, {
    timeouts,
    defaultTimeout,
    getSession,
    onEvent: (type: string, payload: any) => emitter.emit(type, payload),
  });

  // 5e. Wire the inbound side: every well-formed `<type>-response` envelope the
  //     transport accepts (source + origin gated) is routed into the codec —
  //     the single entry point that correlates it to a pending call, an active
  //     stream, or the unknown-frame `onEvent` sink. Without this line the
  //     engine can post requests but never observe a reply. The subscription is
  //     owned by the transport and torn down with it on `disconnect()`.
  transport.onResponse((env) => codec.handleResponse(env));

  // 6. Assemble the sugar namespaces over the one codec + session store.
  //    `pay` additionally gets a live accessor for the session's genericUseSeed —
  //    the key that authenticates `pay.bsv({ broadcast: true })` requests against
  //    the Metanet broadcast API (established by connect(), rotates on re-connect).
  const pay = makePay(codec, () => session.genericUseSeed);
  const feed = makeFeed(codec);
  const tx = makeTx(codec);
  const proof = makeProof(codec);
  const geo = makeGeo(codec);
  const qr = makeQr(codec);
  const util = makeUtil(codec);
  // identity verification is entirely client-side (no codec dependency); the
  // factory takes no arguments (see commands/identity.ts + BUILD_SPEC).
  const identity = makeIdentity();
  const connectSugar = makeConnect(codec, setSession);

  /**
   * `capabilities()` implementation.
   * Reads the *bundled* manifest and returns only commands the parent actually
   * negotiated (so an app can't advertise a capability the current parent lacks).
   * With a `method` argument it returns that one command's slice (or `undefined`).
   */
  function capabilities(): Record<string, unknown>;
  function capabilities(method: string): Record<string, unknown> | undefined;
  function capabilities(method?: string): Record<string, unknown> | Record<string, unknown> | undefined {
    // The manifest's command map, typed loosely (it's validated JSON at build).
    const commands = manifest.commands as Record<string, Record<string, unknown>>;

    if (method !== undefined) {
      // A single command: only expose it if it was negotiated AND exists.
      if (!negotiated.capabilities.has(method)) return undefined;
      return commands[method];
    }

    // No argument: the slice of the manifest for every negotiated command.
    const slice: Record<string, unknown> = {};
    for (const name of negotiated.capabilities) {
      const entry = commands[name];
      if (entry) slice[name] = entry;
    }
    return slice;
  }

  /**
   * `disconnect()` — deterministic teardown. Order matters: dispose the codec
   * first (rejects every pending call with `ERR_DISCONNECTED`, clears timers),
   * then the transport (removes the window listener), then notify listeners and
   * drop them so the client is fully inert and garbage-collectable.
   */
  const disconnect = (): void => {
    codec.dispose();
    transport.dispose();
    emitter.emit('disconnect');
    emitter.clear();
  };

  // The flat facade. `on`/`off` bind straight to the emitter; the `NinjaEvents`
  // overloads on the interface give callers typed event names while the runtime
  // stays a simple string-keyed emitter.
  const ninja: Ninja = {
    call: (method, params, opts) => codec.call(method, params, opts),
    on: (event: string, fn: (...args: any[]) => void) => emitter.on(event, fn),
    off: (event: string, fn: (...args: any[]) => void) => emitter.off(event, fn),
    connect: connectSugar,
    pay,
    feed,
    tx,
    proof,
    geo,
    qr,
    clipboard: util.clipboard,
    openLink: util.openLink,
    identity,
    tokens,
    protocol: negotiated.protocol,
    negotiated,
    capabilities,
    disconnect,
  };

  return ninja;
}

/* ------------------------------------------------------------------ *
 * Public re-exports — one import path for the whole contract.
 * ------------------------------------------------------------------ */

/**
 * `createNinja` — a friendlier alias for `connect`. Some hosts read "connect" as
 * "open a socket"; `createNinja()` reads as "make me a client". Same function.
 */
export { connect as createNinja };

/** The typed error class + its narrowing guard (branch on `err.code`, localize with `t(code)`). */
export { NinjaError, isNinjaError } from './errors';

/** The entire shared type contract (identities, params/results, options, events). */
export * from './types';

/** Named ICP ledger aliases so callers never hardcode canister ids (`tokens.ckUSDC`). */
export { tokens } from './tokens';

/**
 * The BSV broadcast client — for two-step flows: authorize now with
 * `pay.bsv(recipients, { broadcast: false })`, finalize later with
 * `broadcastRawTx(rawTxHex, me.genericUseSeed)`. `pay.bsv`'s default
 * (`broadcast: true`) already does both steps in one call.
 */
export {
  broadcastRawTx,
  broadcastRawTxs,
  signBroadcastRequest,
  DEFAULT_BROADCAST_URL,
} from './broadcast';
export type { BroadcastOptions, BroadcastTxResult } from './broadcast';

/**
 * ZK proof verification — the same functions behind `ninja.identity`, exported
 * top-level so a SERVER (or any Node process holding a received ProofEnvelope)
 * can verify proofs without constructing an iframe client:
 *   `verifyIdentityProof(envelope, canonicalId, pub)` → boolean
 *   `verifyProofOrThrow(envelope, canonicalId, pub)`  → void | ERR_PROOF_INVALID
 * Verification is fully offline: the Groth16 verification keys are EMBEDDED in
 * the bundle and SHA-256-pinned (`VKEY_SHA256`); a corrupted bundle throws
 * ERR_VKEY_INTEGRITY instead of verifying anything (fail closed).
 */
export { verifyIdentityProof, verifyProofOrThrow } from './commands/identity';

/**
 * `decodeCanonicalId(canonicalId)` → `{ version, anchorHex, seedCommitment? }`.
 * Decodes BOTH identity versions of the self-describing `me.canonicalId` string:
 *   V0 → `{ version: 0, anchorHex }`  (anchor = `hash160(pubkey)`, the 40-hex pkh)
 *   V1 → `{ version: 1, anchorHex, seedCommitment }` (anchor = the 32-byte field)
 * Pure format decode — no ZK verification (see `ninja.identity.decodeCanonicalId`).
 * Exported top-level so a server can read the version + anchor without a client.
 */
export { decodeCanonicalId, V0_CANONICAL_ID_VERSION_BYTE } from './zk/spec';
export { VKEY_SHA256, getVerifiedVkey } from './zk/vkeys';
export type { Groth16Vkey, VkeyCurve } from './zk/vkeys';

// Re-export the response payload type by name too — a very common catch-site need
// (`(e.payload as ResponsePayload)`), and cheap to surface explicitly.
export type { ResponsePayload };
