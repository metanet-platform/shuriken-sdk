/**
 * shuriken-sdk — shared type contract.
 *
 * WHAT: every public and wire-level type the SDK uses, in one place.
 * WHY:  this file is the single TypeScript contract that all modules import
 *       from. The `manifest.json` (machine-readable source of truth) and this
 *       file are kept in lockstep by `scripts/generate.ts` and a conformance
 *       test, so docs, runtime validation, and types can never drift apart —
 *       the exact failure that fractured the ~15 hand-copied SDKs.
 *
 * The design in one line: a uniform, JSON-RPC-shaped `call(method, params)`
 * core, with typed sugar (`ninja.pay.bsv(...)`) generated over it.
 */

/* ------------------------------------------------------------------ *
 * 1. Wire envelope — FROZEN, byte-compatible with the live parent.
 *    (metanet_frontend/src/services/appSignaler.js)
 * ------------------------------------------------------------------ */

/** The constant marker the parent filters every message on. Never changes. */
export const WIRE_COMMAND = 'ninja-app-command' as const;

/** The 12 real commands an embedded app can send. This is the closed API surface. */
export type NinjaMethod =
  | 'connection'
  | 'pay'
  | 'create-post'
  | 'generate-proof'
  | 'full-transaction'
  | 'token-history'
  | 'open-link'
  | 'write-clipboard'
  | 'qr-scan'
  | 'qr-scan-stop'
  | 'geolocation'
  | 'geolocation-stop';

/**
 * Request envelope (app -> parent). The SDK builds this; callers never see it.
 * `detail.ref` is the correlation id (our JSON-RPC `id`); `detail.type` is the
 * method (our JSON-RPC `method`); the remaining `detail` fields are the params.
 */
export interface RequestEnvelope<P = Record<string, unknown>> {
  command: typeof WIRE_COMMAND;
  /** Echoed back by the parent as the response `type` root. */
  type: typeof WIRE_COMMAND;
  detail: { type: NinjaMethod | (string & {}); ref: string } & P;
}

/**
 * Response envelope (parent -> app). One `type` per method: `<method>-response`.
 * `payload.ref` correlates back to the request. `signature` is verified against
 * the session public key BEFORE the SDK ever resolves the promise.
 *
 * The index signature exists because the parent puts documented EXTRAS at the
 * envelope's top level — OUTSIDE the signed payload — on the connection
 * response: `genericUseSeed` (fixed per-user-per-app(-salt) 32-byte hex seed,
 * sent on BOTH V0 and V1) and `icIdentityPackage` (time-bounded ICP delegation).
 * The codec preserves them; `connect()` lifts them onto the ConnectResult.
 */
export interface ResponseEnvelope<R = Record<string, unknown>> {
  command: typeof WIRE_COMMAND;
  /** e.g. "pay-response", "connection-response". */
  type: `${string}-response`;
  payload: ResponsePayload & R;
  /** hex signature over sha256(JSON.stringify(payload)); see signature.ts. */
  signature?: string;
  /** Documented top-level extras (connection response): genericUseSeed, icIdentityPackage, … */
  [extra: string]: unknown;
}

/** Fields present on every response payload. */
export interface ResponsePayload {
  /** Correlation id, echoed from the request. */
  ref: string;
  success: boolean;
  /** Standardized code; drives NinjaError.code. `OK_SUCCESS` on success. */
  responseCode: NinjaResponseCode;
  /** `Date.now().toString()` — a STRING on the wire; the SDK parses to number. */
  timestamp?: string;
  /** Streaming responses (geolocation/qr) set this true on the terminal frame. */
  isFinal?: boolean;
}

/* ------------------------------------------------------------------ *
 * 2. Response / error codes.
 * ------------------------------------------------------------------ */

/** Success sentinel returned by the parent. */
export type OkCode = 'OK_SUCCESS';

/**
 * Every error code the SDK can surface as `NinjaError.code`.
 * - Codes WITHOUT the `ERR_`/lowercase prefix come from the platform handlers.
 * - Codes marked "(client)" are raised locally by the SDK before/around the wire.
 * Returned as snake_case/SCREAMING codes so the host app can localize with t(code).
 */
export type NinjaErrorCode =
  // ---- platform handler codes (from metanet_frontend handlers) ----
  | 'ERR_ABORTED'              // user cancelled a consent overlay
  | 'ERR_REJECTED'             // legacy user-cancel code (create-post overlay); treat like ERR_ABORTED
  | 'ERR_POST_FAIL'            // create-post: the post failed to publish
  | 'ERR_MISSING_PARAMS'
  | 'ERR_NOT_SUPPORTED'
  | 'ERR_UNSUPPORTED_TOKEN'    // pay: unknown token/ledger
  | 'ERR_MULTIPLE_RECIPIENTS'  // pay: ICP/KDA allow a single recipient only
  | 'ERR_ICP_PREP_FAILED'
  | 'ERR_KDA_PREP_FAILED'
  | 'ERR_NO_DATA'              // qr-scan: closed with no result
  | 'ERR_TX_NOT_FOUND'         // full-transaction: unknown txid
  | 'ERR_UNKNOWN'
  | 'invalid_salt'             // connection: salt failed /^[A-Za-z0-9._-]{1,64}$/
  | 'connection_failed'
  | 'user_denied'              // generate-proof: user declined
  | 'app_proof_requires_v1'    // generate-proof: identity is V0, app proofs need V1
  // ---- client-side codes (raised by the SDK itself) ----
  | 'ERR_TIMEOUT'              // (client) no response within the deadline
  | 'ERR_SIGNATURE'            // (client) response signature failed verification
  | 'ERR_NO_BROADCAST_KEY'     // (client) pay.bsv broadcast:true but no genericUseSeed captured — connect() first
  | 'ERR_BROADCAST_FAILED'     // (client) the metanet.ninja broadcast API rejected the tx
  | 'ERR_ORIGIN'              // (client) response from a disallowed origin
  | 'ERR_NOT_EMBEDDED'        // (client) no parent window — app opened standalone
  | 'ERR_VALIDATION'          // (client) params failed local schema validation
  | 'ERR_DISCONNECTED';       // (client) transport torn down while awaiting

/** Any responseCode, success or error. */
export type NinjaResponseCode = OkCode | NinjaErrorCode | (string & {});

/* ------------------------------------------------------------------ *
 * 3. Identity — the V0/V1 discriminated union (the core correctness trap).
 *
 * V0 (legacy, still LIVE): a single `wallet` object; the parent signs with the
 *   root/session key. Distinguished by `version: 0`.
 * V1 (the go-forward standard): purpose-scoped `identities`; the parent signs
 *   with the APP-SPECIFIC key (`app.pub`). Distinguished by `version: 1`.
 *
 * Modeled as a discriminated union so TypeScript FORCES a `version` check before
 * you can read version-specific fields — you physically cannot write the mixup
 * that broke every hand-copied SDK. `raw` keeps every original field reachable.
 * ------------------------------------------------------------------ */

/** A Groth16 identity proof (see generate-proof). */
export interface Groth16Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
}

/** The verifiable envelope wrapping a Groth16 proof for one purpose. */
export interface ProofEnvelope {
  scheme: 'metanet-zk-identity-v1';
  purpose: ProofPurpose;
  seedCommitment: string;
  proof: Groth16Proof;
  /** app proofs only: `<appId>:<hash160(salt)>` or `hash160(appUrl)`. */
  assetId?: string;
}

/**
 * The CORE identity purposes the platform ships today. This is the core set —
 * future platform versions may add more purposes, including custom namespaces,
 * and the SDK forwards unknown purposes untouched (they surface verbatim on
 * the normalized V1 identity under their own key, and always via `me.raw`),
 * so a new purpose works without an SDK release.
 *
 * The asymmetry to know: `'app'` is a proof purpose but NOT a chain — it is
 * the always-shared session signer. `'content'` is a pure key purpose (a
 * `pub` + optional proof, NO chain address field).
 */
export const CORE_IDENTITY_PURPOSES = ['app', 'bsv', 'icp', 'kda', 'content'] as const;

/** One of the core identity purposes shipped today. */
export type CorePurpose = (typeof CORE_IDENTITY_PURPOSES)[number];

/**
 * Purposes that can be requested/shared as V1 identities — every core purpose
 * except `'app'` (which is always shared; it's the session signer).
 */
export type ChainKind = Exclude<CorePurpose, 'app'>;

/**
 * Purposes that are real ledgers with wallets/history (`content` is a pure
 * key purpose — no chain, no wallet endpoint, no transaction history).
 */
export type LedgerChainKind = Exclude<ChainKind, 'content'>;

/**
 * Any proof purpose: a core purpose today, or a future/custom namespace
 * string (`string & {}` keeps core-purpose autocomplete while staying open).
 */
export type ProofPurpose = CorePurpose | (string & {});

/** V0 identity: one wallet object, root-key signed. */
export interface IdentityV0 {
  version: 0;
  anonymous: false;
  canonicalId: string;
  wallet: {
    address: string;
    publicKeyHex: string;      // the key the parent signs responses with (secp256k1)
    rootPrincipal?: string;
    bsvPubKey?: string;
    canonicalId?: string;
  };
}

/**
 * V1 identity: purpose-scoped keys, app-key signed.
 *
 * Core purposes are typed explicitly below. UNKNOWN purposes (future platform
 * additions / custom namespaces) still surface: the normalizer passes their
 * `identities` entry through verbatim under its own key, reachable via the
 * index signature (and always via `me.raw`), so new purposes need no SDK release.
 */
export interface IdentityV1 {
  version: 1;
  anonymous: false;
  canonicalId: string;
  /** Signs every response; the verification key for this session. */
  app: { pub: string; proof?: ProofEnvelope };
  bsv?: { address: string; pub: string; proof?: ProofEnvelope };
  icp?: { principal: string; pub: string; proof?: ProofEnvelope };
  kda?: { account: string; pub: string; proof?: ProofEnvelope };
  /** Pure key purpose — a `pub` (+ optional proof), NO chain address field. */
  content?: { pub: string; proof?: ProofEnvelope };
  proofs: Partial<Record<ProofPurpose, ProofEnvelope>>;
  /** Forward-compat: purposes the SDK doesn't know yet, passed through verbatim. */
  [purpose: string]: unknown;
}

/** No connected identity. */
export interface IdentityAnonymous {
  anonymous: true;
  version?: undefined;
  canonicalId: null;
}

export type NinjaIdentity = IdentityV0 | IdentityV1 | IdentityAnonymous;

/** What `ninja.connect()` resolves to: normalized identity + connection state + raw escape hatch. */
export type ConnectResult = NinjaIdentity & {
  connected: boolean;
  /** The full, untouched connection-response payload for version-specific fields. */
  raw: Record<string, unknown>;
  /**
   * Fixed 32-byte hex seed, deterministically derived per user+app(+salt) —
   * delivered on BOTH V0 and V1 (V1 re-keys it when a `salt` is sent). Arrives
   * at the envelope's top level (outside the signed payload). Safe to store;
   * the SDK also keeps it in the session and signs `pay.bsv` broadcast
   * requests with it, so most apps never touch it directly.
   */
  genericUseSeed?: string;
  /**
   * Time-bounded ICP delegation package (delegatee key + signed chain), when
   * the parent issued one. Envelope top-level extra, like `genericUseSeed`.
   */
  icIdentityPackage?: unknown;
};

/* ------------------------------------------------------------------ *
 * 4. Per-command param + result types (typed sugar surface).
 * ------------------------------------------------------------------ */

/**
 * connection
 *
 * `connect()` is RE-CALLABLE — it is the canonical way to request identities
 * or proofs later, incrementally: already-approved items resolve silently
 * (no overlay), while any NEW item re-prompts the user with the full list.
 * Approvals persist across visits; denials are per-visit.
 */
export interface ConnectParams {
  /** Identities to share (V1); harmless on V0. */
  request?: ChainKind[];
  /** Also mint Groth16 proofs for these purposes (core, or a future/custom namespace — forwarded untouched). */
  proofs?: ProofPurpose[];
  /** Optional per-app re-keying salt; must match /^[A-Za-z0-9._-]{1,64}$/. */
  salt?: string;
  /** Nav background hint; sanitized to a css color/gradient parent-side. */
  navbg?: string;
  /**
   * Wallet-level info to also request (V1): the parent answers with a
   * `payload.wallets` array of `{ chain, address|principal|account, pub }`.
   * Distinct from `request` (which shares purpose-scoped *identities*); this
   * asks for the user's wallet endpoints per chain. Harmless on V0 parents
   * (ignored, like every other V1 declaration field). Only real ledgers have
   * wallet endpoints — `content` is a pure key purpose, so it has none.
   */
  wallets?: LedgerChainKind[];
}

/** pay — BSV */
export interface BsvRecipient {
  address?: string;
  /** amount in satoshis */
  sats?: number;
  /** amount in USD — a shortcut for `fiatValue` with `currency: 'USD'`. */
  usd?: number;
  /**
   * amount in fiat; pair with `currency` (defaults to USD). The platform converts
   * it to satoshis via its FX rate — the SDK just forwards it (no conversion).
   */
  fiatValue?: number;
  /**
   * Fiat currency for `fiatValue`/`usd` (e.g. 'USD','EUR','GBP','JPY',…). Defaults
   * to 'USD'. Must be a platform-supported currency; the platform does the FX.
   */
  currency?: string;
  note?: string;
  /** fee-only recipient */
  fee?: 'APP_GENERIC' | 'AI_IMG' | (string & {});
}
/** Options for `ninja.pay.bsv(recipients, opts)`. */
export interface BsvPayOptions {
  /**
   * `true` (the default): after the user authorizes the payment, the SDK
   * finalizes it — it POSTs the returned raw tx to the Metanet broadcast API
   * (`api.metanet.ninja/data/api`), signing the request with the session's
   * `genericUseSeed`, and resolves with the network `txid`.
   * `false`: stop after authorization — the UTXOs are signed/authorized but
   * NOT broadcast; you get the `rawTxHex` to inspect, chain, batch, or
   * broadcast yourself later (see `broadcastRawTx`).
   */
  broadcast?: boolean;
  /** App identifier recorded with the broadcast (defaults to 'shuriken-sdk'). */
  source?: string;
}

export interface BsvPayResult {
  /** The signed raw transaction hex (always returned, broadcast or not). */
  rawTxHex: string;
  responseCode: OkCode;
  /** Whether the SDK broadcast the tx to the network. */
  broadcast: boolean;
  /** The network txid — present only when `broadcast` is true. */
  txid?: string;
}

/** pay — ICP (single recipient) */
export interface IcpPayParams {
  token: string;      // named ledger alias, e.g. 'ckUSDC' (see tokens.ts) or a raw ledger id
  to: string;         // principal
  /**
   * Amount in WHOLE token units (a decimal), e.g. `1.5` ckUSDC — NOT base units
   * (no e8s/bigint). The platform's overlay formats it using the ledger's
   * decimals and converts to base units for the transfer; the SDK forwards as-is.
   */
  amount: number;
  memo?: string;
}
export interface IcpPayResult { transferOutcome: bigint }

/** pay — KDA (single recipient) */
export interface KdaPayParams {
  to: string;
  amount: number;
  /**
   * Kadena chain id. Currently ONLY `'2'` is supported for sending from balance
   * (the platform's funding chain); passing anything else throws
   * `ERR_NOT_SUPPORTED`. Defaults to `'2'`. More chains may be supported later.
   */
  chainId?: '2';
}
export interface KdaPayResult { requestKey: string; chainId: string }

/** create-post */
export interface CreatePostParams {
  headline: string;
  nftDescription?: string;
  previewAsset?: File | Blob;
  appEmbed?: { url: string; type?: 'game' | 'app' | (string & {}); shape?: 'landscape' | 'portrait' | 'square' };
}
export interface CreatePostResult { postId: string }

/**
 * generate-proof — the APP-identity-proof shortcut. There is deliberately no
 * `purpose` param: the parent only ever mints the `app` proof here. Request
 * proofs for other purposes via `ninja.connect({ request, proofs })` — the
 * canonical, re-callable way (approved items resolve silently, new items
 * re-prompt the full list; approvals persist, denials are per-visit).
 */
export interface GenerateProofParams { reason?: string }
export interface GenerateProofResult {
  canonicalId: string;
  pub: string;
  proof: Groth16Proof;
  seedCommitment: string;
  appId?: string;
  appUrl?: string;
}

/** full-transaction */
export interface FullTransactionResult { txid: string; rawHex: string; bumpHex?: string }

/** token-history — ledgers only (`content` has no chain, hence no history). */
export interface TokenHistoryParams { chain?: LedgerChainKind; limit?: number; offset?: number }
export interface TokenHistoryResult {
  transactions: unknown[];
  hasMore: boolean;
  totalCount: number;
}

/** geolocation (streaming) */
export interface GeoFix {
  latitude: number;
  longitude: number;
  accuracy?: number;
  timestamp: number;
  isFinal?: boolean;
}

/** qr-scan (streaming) */
export interface QrScanResult { rawValue: string; parsed?: unknown }

/* ------------------------------------------------------------------ *
 * 5. Client construction + call options.
 * ------------------------------------------------------------------ */

/** Per-command timeout table (ms). Any omitted method uses `default`. */
export type TimeoutTable = { default: number } & Partial<Record<NinjaMethod, number>>;

export interface ConnectOptions {
  /**
   * Allowed parent origins for INBOUND messages. The SDK rejects any response
   * from an origin not in this list (prod). Required unless `dev` is set.
   */
  allowedOrigins?: string[];
  /**
   * Relaxes origin checks to localhost ONLY, and only when explicitly true.
   * Replaces the old silent global `localhost=true` bypass. Never ship `true`.
   */
  dev?: boolean;
  /** Protocol preference for the handshake; frozen apps pass [0]. Default [1, 0]. */
  protocols?: number[];
  /** Milliseconds to wait for `ninja-ready` before assuming a legacy parent. */
  readyTimeout?: number;
  /** Per-command timeouts. */
  timeoutMs?: Partial<TimeoutTable>;
  /** Inject the parent window (defaults to window.parent). Useful for tests. */
  targetWindow?: Window;
}

export interface CallOptions {
  /** Override the timeout for this call. */
  timeoutMs?: number;
  /** Abort the call (removes the pending listener + rejects with ERR_DISCONNECTED). */
  signal?: AbortSignal;
  /** Skip local schema validation (advanced/forward-compat). */
  skipValidation?: boolean;
  /**
   * Advanced: resolve with `{ payload, envelope }` instead of the bare payload,
   * exposing the envelope's documented top-level extras (the connection
   * response carries `genericUseSeed` / `icIdentityPackage` OUTSIDE the signed
   * payload). Used internally by `connect()`; rarely needed by apps.
   */
  withEnvelope?: boolean;
}

/** What `call(..., { withEnvelope: true })` resolves with. */
export interface CallWithEnvelope<T = ResponsePayload> {
  payload: T;
  envelope: ResponseEnvelope;
}

/** A live subscription to a streaming command. */
export interface Subscription {
  /** Stops the stream: sends the `<method>-stop` message and releases the ref. */
  stop(): void;
  /** True until stop() is called or a final frame arrives. */
  readonly active: boolean;
}

/** Events the SDK emits to the app (not wire responses). */
export interface NinjaEvents {
  disconnect: () => void;
  connect: (id: ConnectResult) => void;
  /** Any unrecognized `<type>-response` is routed here, never dropped. */
  [key: `${string}-response`]: (payload: ResponsePayload) => void;
}

/** Runtime capability info negotiated at handshake (or defaulted for legacy). */
export interface Negotiated {
  protocol: number;
  capabilities: Set<NinjaMethod | string>;
  ledgers?: string[];
}
