# BUILD_SPEC — internal module contracts (implementation guide)

> Not published to consumers. This pins the exact signatures every `src/` module
> exports so the implementation is cohesive. All types come from `./types`. Import
> the error class from `./errors`. Heavy `what + why` inline comments are required
> on every export. No runtime deps except `@noble/curves` / `@noble/hashes`
> (inlined at build).

## src/protocol/envelope.ts
```ts
import { WIRE_COMMAND, type RequestEnvelope, type ResponseEnvelope, type NinjaMethod } from '../types';
export function buildRequest<P extends object>(method: NinjaMethod | string, ref: string, params: P): RequestEnvelope;
export function isResponseEnvelope(data: unknown): data is ResponseEnvelope; // command===WIRE_COMMAND && type endsWith '-response' && payload?.ref is string
export function responseMethod(type: string): string; // 'pay-response' -> 'pay'
```

## src/protocol/correlation.ts
```ts
export function newRef(): string; // crypto.randomUUID(); guaranteed <=256 chars, sanitizeV1Ref-safe
```

## src/protocol/signature.ts
```ts
// Verify hex signature over sha256(utf8(JSON.stringify(payload))). secp256k1.
// sessionPub null => not yet established (e.g. the connection-response itself); return true (origin check still applies) and DOCUMENT this.
// NOTE: the exact V1 curve must be confirmed against appSignaler.signWalletPayload before v1.0 — leave a clear TODO. Default both versions to secp256k1.
export function verifyResponse(payload: unknown, signature: string | undefined, sessionPub: string | null, version: 0 | 1 | undefined): boolean;
export function sha256Hex(input: string): string;
```

## src/protocol/normalize.ts
```ts
import type { ConnectResult, NinjaIdentity } from '../types';
// Map a raw connection-response payload -> discriminated ConnectResult (+ .raw).
// V0: payload.version===0 || payload.wallet present. V1: payload.version===1 || payload.identities present. else anonymous.
export function normalizeConnection(payload: Record<string, unknown>): ConnectResult;
export function sessionPubOf(id: NinjaIdentity): string | null;       // V0 wallet.publicKeyHex, V1 app.pub, else null
export function sessionVersionOf(id: NinjaIdentity): 0 | 1 | undefined;
```

## src/tokens.ts
```ts
// Named ICP ledger aliases so callers never hardcode canister ids. Confirm ids before v1.0.
export const tokens: Readonly<Record<string, string>>; // { ICP:'ryjl3-tyaaa-aaaaa-aaaba-cai', ckUSDC:'xevnm-gaaaa-aaaar-qafnq-cai', ckBTC:'mxzaz-hqaaa-aaaar-qaada-cai', ... }
export function resolveLedger(nameOrId: string): string; // alias -> id, or passthrough if already an id
```

## src/transport/originPolicy.ts
```ts
export function makeOriginPolicy(opts: { allowedOrigins?: string[]; dev?: boolean }): (origin: string) => boolean;
// dev:true => allow localhost/127.0.0.1 only. else => origin must be in allowedOrigins. Empty allowedOrigins + !dev => throw at construction (misconfig).
```

## src/transport/transport.ts
```ts
import type { RequestEnvelope, ResponseEnvelope } from '../types';
export class Transport {
  constructor(targetWindow: Window, isAllowedOrigin: (o: string) => boolean);
  post(env: RequestEnvelope): void;                       // targetWindow.postMessage(env, '*')
  onResponse(cb: (env: ResponseEnvelope, origin: string) => void): () => void;   // filters: event.source===targetWindow && isResponseEnvelope && isAllowedOrigin(origin)
  onRaw(cb: (data: any, origin: string) => void): () => void;   // for handshake (ninja-ready) — same source/origin gate, no -response filter
  dispose(): void;
}
```

## src/transport/handshake.ts
```ts
import type { Negotiated } from '../types';
export function negotiate(t: Transport, opts: { protocols: number[]; readyTimeout: number; capabilitiesFallback: string[] }): Promise<Negotiated>;
// post {command:'ninja-app-command', type:'ninja-hello', detail:{protocols, sdkVersion}}; resolve on a raw 'ninja-ready' {protocol,capabilities,ledgers}; on timeout resolve assume-legacy {protocol:0, capabilities:capabilitiesFallback}.
```

## src/protocol/codec.ts (the engine)
```ts
import type { CallOptions, ResponseEnvelope, Subscription } from '../types';
export interface Session { pub: string | null; version: 0 | 1 | undefined; genericUseSeed: string | null; }
export class Codec {
  constructor(t: Transport, opts: { timeouts: Record<string, number>; defaultTimeout: number; getSession: () => Session; onEvent: (type: string, payload: any) => void; });
  call<T = any>(method: string, params?: object, opts?: CallOptions): Promise<T>;   // mint ref, post, Map<ref,pending> with timer; on response: verify signature (getSession) then resolve payload or reject NinjaError.fromPayload; AbortSignal + timeout => reject + cleanup. { withEnvelope:true } resolves { payload, envelope } (connect() needs the top-level extras).
  stream(method: string, params: object, onFrame: (payload: any) => void, opts?: CallOptions): Subscription; // multi-frame; stop() posts `${method}-stop` + unregisters; isFinal frame auto-stops
  streamIterable<T = any>(method: string, params?: object, opts?: CallOptions): AsyncIterable<T> & { stop(): void };
  handleResponse(env: ResponseEnvelope): void;   // route to pending (one-shot) OR stream handlers OR onEvent(unknown)
  dispose(): void;   // reject all pending with ERR_DISCONNECTED, clear timers
}
```

## src/commands/*.ts (typed sugar factories — thin wrappers over codec.call/stream)
```ts
// connect.ts
export function makeConnect(codec: Codec, setSession: (s: Session) => void): (params?: ConnectParams) => Promise<ConnectResult>;
// pay.ts
export function makePay(codec: Codec, getBroadcastKey: () => string | null): { bsv(r: BsvRecipient[], opts?: BsvPayOptions): Promise<BsvPayResult>; icp(p: IcpPayParams): Promise<IcpPayResult>; kda(p: KdaPayParams): Promise<KdaPayResult>; };
// feed.ts -> { createPost }, tx.ts -> { get, history }, proof.ts -> { generate }
// geo.ts -> { current(): Promise<GeoFix>; watch(): AsyncIterable<GeoFix> & {stop()} }
// qr.ts -> { scan(onResult): Subscription }
// util.ts -> { openLink(url): Promise<void>; clipboard: { write(text): void } }
// identity.ts -> { verifyProof(proof: ProofEnvelope, canonicalId: string): boolean }  (client-side check; stub returns true for well-formed until the vkey is bundled)
```

## src/index.ts (public entry)
```ts
export async function connect(options?: ConnectOptions): Promise<Ninja>;   // build transport+originPolicy, negotiate(), codec, session store; assemble Ninja
export { connect as createNinja };
export { NinjaError, isNinjaError } from './errors';
export * from './types';
export { tokens } from './tokens';
export { broadcastRawTx, broadcastRawTxs, signBroadcastRequest, DEFAULT_BROADCAST_URL } from './broadcast';
// Ninja object shape:
//   call, on, off, connect(=makeConnect), pay, feed, tx, proof, geo, qr, clipboard, openLink, identity, tokens,
//   protocol:number, get capabilities():Set, capabilities(method?)=>manifest slice, negotiated:Negotiated, disconnect()
// capabilities() reads the bundled manifest.json (import manifest from '../manifest.json').
```

## src/react.tsx (subpath "shuriken-sdk/react")
```tsx
export function NinjaProvider(props: NinjaProviderProps): JSX.Element; // request/proofs/salt/navbg/autoConnect/options + gate/loader/renderAnonymous/renderError/authenticate/onConnected/onAuthenticated/onError
export function useNinja(): Ninja | null;
export function useConnection(): { me: ConnectResult | null; status: NinjaStatus; error: NinjaError | null; reconnect(): void };
export function useSession<T = unknown>(): { me: ConnectResult | null; session: T | null; status: NinjaStatus; error: NinjaError | null; ready: boolean; reconnect(): void };
export function usePayment(): { pay: Ninja['pay']; pending: boolean; error: NinjaError | null };
export function useGeolocation(): { fix: GeoFix | null; watching: boolean; start(): void; stop(): void };
export function useQrScanner(): { last: QrScanResult | null; scanning: boolean; start(onResult?): void; stop(): void };
// react is a peer dep; import from 'react'. Handle SSR (no window) gracefully.
```

## scripts/generate.ts
```ts
// Reads ../manifest.json and (re)writes generated artifacts. Generate src/generated/capabilities.ts (typed snapshot) and validate that manifest command keys match NinjaMethod. Keep it minimal but real (no placeholder that throws).
```
