/**
 * shuriken-sdk — the Codec: the request/response engine at the heart of the SDK.
 *
 * WHAT: turns the raw `postMessage` envelope traffic (see PROTOCOL.md) into three
 *       ergonomic primitives the rest of the SDK is built on:
 *         - `call()`         — a one-shot request/response Promise (JSON-RPC style),
 *         - `stream()`       — a callback subscription over multi-frame responses,
 *         - `streamIterable()`— the same stream exposed as an `AsyncIterable`.
 *       Plus `handleResponse()` (the single inbound router) and `dispose()`.
 *
 * WHY:  every prior hand-copied SDK re-implemented correlation/timeouts/verification
 *       ad hoc, and each got a subtle detail wrong (leaked timers on abort, resolving
 *       BEFORE verifying the signature, colliding refs across concurrent calls,
 *       dropping unknown frames, never sending the stream `-stop`). Centralizing all of
 *       it here — once, carefully, with the signature verified *before* any promise
 *       resolves — is the whole reason this package exists. This file is the crown jewel;
 *       it is commented in the "what + why" style on every export and every non-obvious step.
 *
 * INVARIANTS this module guarantees:
 *   1. A `ref` is minted per call and is the ONLY correlation key. Concurrent calls
 *      with distinct refs never collide.
 *   2. The signature is verified (against the *current* session key) BEFORE a response
 *      is ever handed to the caller. An unverifiable payload rejects `ERR_SIGNATURE`
 *      and never surfaces as data (PROTOCOL.md "Signature verification").
 *   3. Exactly one settlement per pending entry, and the entry + its timer are torn
 *      down on EVERY exit path (resolve / reject / timeout / abort / dispose). No leaks.
 *   4. Unknown `<type>-response` frames are never dropped — they route to `onEvent`.
 */

import type { CallOptions, ResponseEnvelope, ResponsePayload, Subscription } from '../types';
import { NinjaError } from '../errors';
import { buildRequest } from './envelope';
import { newRef } from './correlation';
import { verifyResponse } from './signature';

/**
 * The session snapshot the codec needs at *verification time*.
 *
 * WHY a getter, not a stored value: the session is established by the very first
 * `connection` call and can change (reconnect / version upgrade). The codec must
 * verify each response against whatever key is current *now*, so `Codec` holds a
 * `getSession` thunk (injected by index.ts) rather than a frozen copy. During the
 * connection-response itself `pub` is legitimately `null` — signature.ts treats a
 * null key as "not yet established" and passes (origin check still gates it).
 */
export interface Session {
  /** The public key (hex) the parent signs responses with, or null before connect. */
  pub: string | null;
  /** Identity version — selects which key/verification rules apply (V0 vs V1). */
  version: 0 | 1 | undefined;
  /**
   * The connection's `genericUseSeed` (32-byte hex, per user+app(+salt); sent on
   * BOTH V0 and V1), or null before connect. Not used for response verification —
   * it is the secp256k1 key `pay.bsv({ broadcast: true })` signs the Metanet
   * broadcast-API request with (see src/broadcast.ts). Lives in the session cell
   * so it rotates atomically with the pub/version on every (re)connect.
   */
  genericUseSeed: string | null;
}

/** Minimal shape of the transport the codec drives. Kept structural so tests can fake it. */
interface TransportLike {
  /** Post a request envelope to the parent window (targetOrigin '*'; see PROTOCOL.md). */
  post(env: import('../types').RequestEnvelope): void;
}

/** Constructor options — injected by `connect()` in index.ts. */
export interface CodecOptions {
  /** Per-method timeout table (ms). A method absent here uses `defaultTimeout`. */
  timeouts: Record<string, number>;
  /** Fallback timeout (ms) for any method not in `timeouts` and no per-call override. */
  defaultTimeout: number;
  /** Current session accessor (see `Session`); read fresh on every verification. */
  getSession: () => Session;
  /**
   * Sink for responses that match no in-flight call or active stream. This is the
   * "never drop an unknown frame" escape hatch (PROTOCOL.md forward-compat rule #2):
   * unrecognized `<type>-response` messages are surfaced to `ninja.on(type)`.
   */
  onEvent: (type: string, payload: ResponsePayload) => void;
}

/**
 * A pending one-shot `call()`, tracked in `#pending` keyed by `ref`.
 * `settle` collapses resolve/reject + timer-clear + map-delete into one idempotent
 * step so no exit path can leave a dangling timer or double-settle a promise.
 */
interface Pending {
  /** The method name (for building precise NinjaErrors and choosing timeout). */
  method: string;
  /** Resolve the caller's promise with the verified payload. */
  resolve: (value: unknown) => void;
  /** Reject the caller's promise with a NinjaError. */
  reject: (err: NinjaError) => void;
  /** The timeout handle to clear on settlement. */
  timer: ReturnType<typeof setTimeout>;
  /** Detach the AbortSignal listener (if any) on settlement — avoids a leak. */
  cleanupAbort?: () => void;
  /** Stop the resend interval (if any) on settlement — see CallOptions.resend. */
  cleanupResend?: () => void;
  /**
   * When true, resolve with `{ payload, envelope }` instead of the bare payload —
   * the caller needs the envelope's top-level extras (connection response only:
   * `genericUseSeed` / `icIdentityPackage` live OUTSIDE the signed payload).
   */
  withEnvelope?: boolean;
}

/**
 * An active multi-frame stream (`geolocation` / `qr-scan`), tracked in `#streams`
 * keyed by `ref`. Frames sharing this `ref` are demuxed to `onFrame`; the terminal
 * `isFinal` frame (or an explicit `stop()`) tears it down and posts `<method>-stop`.
 */
interface ActiveStream {
  /** The streaming method — used to derive the paired `<method>-stop` message. */
  method: string;
  /** Deliver each verified frame payload to the subscriber. */
  onFrame: (payload: ResponsePayload) => void;
  /** Deliver a terminal error (bad signature / error frame) to the subscriber, if it can take one. */
  onError?: (err: NinjaError) => void;
  /** Called exactly once when the stream ends (final frame, stop, error, dispose). */
  onEnd?: () => void;
  /** Latches false the instant the stream is no longer live (idempotency guard). */
  active: boolean;
}

/**
 * The engine. One instance per connected `Ninja`. Owns the pending-call map, the
 * active-stream map, and all timer/abort bookkeeping. Constructed by index.ts and
 * fed inbound frames via `handleResponse` (wired to `Transport.onResponse`).
 */
export class Codec {
  /** In-flight one-shot calls, keyed by correlation `ref`. */
  readonly #pending = new Map<string, Pending>();
  /** Live streaming subscriptions, keyed by correlation `ref`. */
  readonly #streams = new Map<string, ActiveStream>();
  /** True after `dispose()` — every subsequent call/stream fails fast, no zombies. */
  #disposed = false;

  readonly #transport: TransportLike;
  readonly #timeouts: Record<string, number>;
  readonly #defaultTimeout: number;
  readonly #getSession: () => Session;
  readonly #onEvent: (type: string, payload: ResponsePayload) => void;

  /**
   * @param t     the transport to post requests through (only `post` is used here;
   *              inbound routing is delivered to us via `handleResponse`).
   * @param opts  timeouts + session accessor + unknown-frame sink (see CodecOptions).
   */
  constructor(t: TransportLike, opts: CodecOptions) {
    this.#transport = t;
    this.#timeouts = opts.timeouts;
    this.#defaultTimeout = opts.defaultTimeout;
    this.#getSession = opts.getSession;
    this.#onEvent = opts.onEvent;
  }

  /* ---------------------------------------------------------------- *
   * Timeout resolution
   * ---------------------------------------------------------------- */

  /**
   * Pick the effective timeout (ms) for a call: explicit per-call override wins,
   * then the per-method table, then the global default. Kept private + tiny so the
   * precedence lives in exactly one place (the hand-copied SDKs scattered it).
   */
  #timeoutFor(method: string, override?: number): number {
    if (typeof override === 'number') return override;
    const perMethod = this.#timeouts[method];
    return typeof perMethod === 'number' ? perMethod : this.#defaultTimeout;
  }

  /* ---------------------------------------------------------------- *
   * call() — one-shot request/response
   * ---------------------------------------------------------------- */

  /**
   * Send one request and resolve with its (signature-verified) result payload.
   *
   * Lifecycle (mirrors PROTOCOL.md "Correlation & lifecycle"):
   *   1. mint a fresh `ref`; register a `Pending` under it BEFORE posting so a
   *      synchronous same-tick response can never race ahead of registration;
   *   2. post the request envelope;
   *   3. arm a timeout that rejects `ERR_TIMEOUT` and cleans up;
   *   4. wire the optional `AbortSignal` to reject `ERR_DISCONNECTED` + clean up;
   *   5. `handleResponse` later verifies the signature, then resolves the payload
   *      or rejects `NinjaError.fromPayload`.
   * Every path tears the entry (and its timer + abort listener) down exactly once.
   *
   * @typeParam T  the caller's expected result shape (typed sugar narrows this).
   */
  call<T = unknown>(method: string, params: object = {}, opts: CallOptions = {}): Promise<T> {
    // Fail fast if the transport is already gone — never register a pending that
    // can only ever time out.
    if (this.#disposed) {
      return Promise.reject(
        new NinjaError('ERR_DISCONNECTED', { method, hint: 'SDK disposed before call' }),
      );
    }

    // Honor an already-aborted signal synchronously: no ref minted, no post.
    if (opts.signal?.aborted) {
      return Promise.reject(
        new NinjaError('ERR_DISCONNECTED', { method, hint: 'aborted before dispatch' }),
      );
    }

    const ref = newRef();

    return new Promise<T>((resolve, reject) => {
      // settle() is the single idempotent teardown+settlement point. It removes the
      // pending entry FIRST (so a duplicate frame can't re-enter), clears the timer,
      // detaches the abort listener, then fulfills the promise. Called on every exit.
      const settle = (fn: () => void): void => {
        const entry = this.#pending.get(ref);
        if (!entry) return; // already settled — ignore any late/duplicate signal.
        this.#pending.delete(ref);
        clearTimeout(entry.timer);
        entry.cleanupAbort?.();
        entry.cleanupResend?.();
        fn();
      };

      // (3) timeout arm — rejects and cleans up if no response arrives in time.
      const timer = setTimeout(() => {
        settle(() =>
          reject(
            new NinjaError('ERR_TIMEOUT', {
              method,
              ref,
              hint: `no response in ${this.#timeoutFor(method, opts.timeoutMs)}ms`,
            }),
          ),
        );
      }, this.#timeoutFor(method, opts.timeoutMs));

      // (4) abort wiring — user cancellation rejects with ERR_DISCONNECTED. We keep a
      // detacher so a normal resolve/timeout doesn't leave this listener attached.
      let cleanupAbort: (() => void) | undefined;
      const signal = opts.signal;
      if (signal) {
        const onAbort = (): void => {
          settle(() =>
            reject(new NinjaError('ERR_DISCONNECTED', { method, ref, hint: 'aborted by caller' })),
          );
        };
        signal.addEventListener('abort', onAbort, { once: true });
        cleanupAbort = () => signal.removeEventListener('abort', onAbort);
      }

      // Resend arming (opt-in liveness, see CallOptions.resend): the envelope is
      // built ONCE and re-posted verbatim (same ref) on an interval, so a parent
      // whose listener attaches after our first post still receives the request.
      // The interval self-stops after `maxResends` and is torn down in settle()
      // on every exit path (response, timeout, abort, dispose).
      const envelope = buildRequest(method, ref, params as Record<string, unknown>);
      let cleanupResend: (() => void) | undefined;
      if (opts.resend && opts.resend.maxResends > 0) {
        const { intervalMs, maxResends } = opts.resend;
        let sent = 0;
        const resendTimer = setInterval(() => {
          sent += 1;
          if (sent > maxResends) {
            clearInterval(resendTimer);
            return;
          }
          this.#transport.post(envelope);
        }, intervalMs);
        cleanupResend = () => clearInterval(resendTimer);
      }

      // (1) register BEFORE (2) posting — closes the sync-response race window.
      this.#pending.set(ref, {
        method,
        // Bridge the untyped payload to the caller's T at the single trusted boundary.
        resolve: (value) => settle(() => resolve(value as T)),
        reject: (err) => settle(() => reject(err)),
        timer,
        cleanupAbort,
        cleanupResend,
        // Thread the caller's envelope request through to handleResponse (which is
        // the only place holding the full envelope when the reply arrives).
        ...(opts.withEnvelope ? { withEnvelope: true } : {}),
      });

      // (2) post. envelope.ts owns the exact wire shape; we never hand-roll it.
      this.#transport.post(envelope);
    });
  }

  /* ---------------------------------------------------------------- *
   * stream() — callback subscription over multi-frame responses
   * ---------------------------------------------------------------- */

  /**
   * Subscribe to a streaming method (`geolocation` / `qr-scan`). Every frame sharing
   * the minted `ref` is verified then delivered to `onFrame`. The stream ends when:
   *   - a frame carries `isFinal: true` (auto-stop — no `-stop` needed, the parent
   *     already closed its side), or
   *   - the caller invokes `stop()` (we post `<method>-stop` and release the ref), or
   *   - `dispose()` tears everything down.
   *
   * Returns a `Subscription` whose `active` flag reflects liveness and whose `stop()`
   * is idempotent. No timeout is armed: streams are open-ended by contract.
   *
   * @param onFrame  invoked per verified frame payload.
   * @param opts     `signal` also stops the stream (abort === stop).
   */
  stream(
    method: string,
    params: object,
    onFrame: (payload: ResponsePayload) => void,
    opts: CallOptions = {},
  ): Subscription {
    return this.#openStream(method, params, onFrame, opts).subscription;
  }

  /**
   * Per-ref stop() closures, so `handleResponse` can auto-stop a stream on its final
   * frame (or abort one on a bad signature) without reaching into the opener's local
   * scope. The single argument `internal` selects whether a `<method>-stop` is echoed.
   * Cleared alongside `#streams`.
   */
  readonly #streamStoppers = new Map<string, (internal?: boolean) => void>();

  /**
   * The shared stream opener behind both `stream()` and `streamIterable()`.
   *
   * WHY factored out: `streamIterable` needs the ActiveStream `record` and the `ref`
   * to attach `onEnd`/`onError` hooks that terminate the async iterator. Returning them
   * here (instead of reverse-engineering the ref from a Subscription) keeps the lifecycle
   * exact and eliminates any guessing. Both entry points therefore share ONE teardown
   * path (`stop`), so `active`, auto-stop, abort, and dispose all agree.
   *
   * @returns the public `subscription`, plus the internal `ref` and `record` so the
   *          iterable wrapper can decorate the stream's end/error hooks.
   */
  #openStream(
    method: string,
    params: object,
    onFrame: (payload: ResponsePayload) => void,
    opts: CallOptions,
  ): { subscription: Subscription; ref: string; record: ActiveStream } {
    const ref = newRef();

    // Liveness lives on the ActiveStream record; `stop()` flips it so both the returned
    // Subscription.active and the internal auto-stop read one source of truth.
    const record: ActiveStream = { method, onFrame, active: true };

    // A subscription that is dead on arrival (disposed, or already-aborted signal). We
    // return this instead of opening a stream that could never receive a frame.
    const deadSubscription: Subscription = { stop: () => {}, get active() { return false; } };

    // stop(): idempotent teardown. `internal=true` means "the parent already ended this
    // stream" (final frame / error frame) so we must NOT echo a `-stop`; a user/abort/
    // signature-driven stop DOES post `<method>-stop` so the parent frees camera/GPS.
    const stop = (internal = false): void => {
      const live = this.#streams.get(ref);
      if (!live) return; // already stopped — idempotent.
      live.active = false;
      this.#streams.delete(ref);
      this.#streamStoppers.delete(ref);
      cleanupAbort?.();
      if (!internal && !this.#disposed) {
        // `${method}-stop` matches the manifest stopType (geolocation-stop / qr-scan-stop).
        // We reuse the same ref so the parent correlates teardown to the exact stream.
        this.#transport.post(buildRequest(`${method}-stop`, ref, {}));
      }
      live.onEnd?.();
    };

    // Abort === stop (cancelling a stream is just an early stop that frees parent-side
    // resources). An already-aborted signal means never open the stream at all.
    let cleanupAbort: (() => void) | undefined;
    const signal = opts.signal;
    if (signal?.aborted) return { subscription: deadSubscription, ref, record };
    if (signal) {
      const onAbort = (): void => stop(false);
      signal.addEventListener('abort', onAbort, { once: true });
      cleanupAbort = () => signal.removeEventListener('abort', onAbort);
    }

    // Disposed before we could start — present an already-dead subscription and detach.
    if (this.#disposed) {
      cleanupAbort?.();
      return { subscription: deadSubscription, ref, record };
    }

    // Register BEFORE posting so a synchronous first frame can't race registration, and
    // expose the auto-stop path to handleResponse via the stopper registry.
    this.#streams.set(ref, record);
    this.#streamStoppers.set(ref, stop);

    // Open the stream with the same envelope builder as call().
    this.#transport.post(buildRequest(method, ref, params as Record<string, unknown>));

    const subscription: Subscription = {
      stop: () => stop(false),
      get active() {
        return record.active;
      },
    };
    return { subscription, ref, record };
  }

  /* ---------------------------------------------------------------- *
   * streamIterable() — the same stream as an AsyncIterable
   * ---------------------------------------------------------------- */

  /**
   * Expose a streaming method as an `AsyncIterable<T>` with a `stop()` method, so
   * callers can write `for await (const fix of ninja.geo.watch()) { ... }`.
   *
   * WHY a queue: producer (inbound frames) and consumer (`for await`) run at different
   * rates. We buffer frames in `queue` and park a waiting consumer in `resolvers`;
   * whichever arrives second is matched to the first. `break`ing the loop triggers the
   * iterator's `return()`, which calls `stop()` → posts `<method>-stop`. This is the
   * ONE place we must get backpressure/cleanup right so no fix is lost or double-delivered.
   */
  streamIterable<T = unknown>(
    method: string,
    params: object = {},
    opts: CallOptions = {},
  ): AsyncIterable<T> & { stop(): void } {
    // Buffered-but-unconsumed frames.
    const queue: T[] = [];
    // Parked consumers awaiting the next frame: resolve => deliver, done flag => end.
    const resolvers: Array<(r: IteratorResult<T>) => void> = [];
    // A terminal error to throw into the consumer (bad signature / error frame).
    let pendingError: NinjaError | null = null;
    // Latches when the stream is finished (final frame / stop / dispose).
    let ended = false;

    // push(): called by the codec when a frame is verified. Either hands the value to a
    // parked consumer immediately, or buffers it for the next pull().
    const push = (value: T): void => {
      if (ended) return;
      const waiter = resolvers.shift();
      if (waiter) waiter({ value, done: false });
      else queue.push(value);
    };

    // finish(): drain the parked consumers with `done` (or an error). Idempotent.
    const finish = (err?: NinjaError): void => {
      if (ended) return;
      ended = true;
      if (err) pendingError = err;
      // Wake every parked consumer so none hangs forever after the stream ends.
      while (resolvers.length) {
        const waiter = resolvers.shift()!;
        waiter({ value: undefined as unknown as T, done: true });
      }
    };

    // Drive the underlying callback stream via the shared opener, which hands us the
    // exact ActiveStream `record` so we can decorate its end/error hooks (no ref
    // guessing). onFrame → push; onEnd (final frame / stop / dispose) → finish;
    // onError (bad signature / error frame / dispose) → finish(err). The AsyncIterable
    // and the callback engine thus share ONE lifecycle.
    const { subscription: sub, record } = this.#openStream(
      method,
      params,
      (payload) => push(payload as unknown as T),
      opts,
    );

    if (record.active) {
      // Attach terminators so a final frame or a verification failure ends the iterator
      // too (not just the callback view). onEnd fires on graceful stop; onError delivers
      // the terminal error to the consumer's next pull().
      record.onEnd = () => finish();
      record.onError = (err) => finish(err);
    } else {
      // The stream was dead on arrival (disposed / pre-aborted signal) — finish now so
      // the consumer's first pull() resolves `done` instead of hanging forever.
      finish();
    }

    const iterator: AsyncIterator<T> = {
      // next(): return a buffered frame, else park until push()/finish() wakes us.
      next: (): Promise<IteratorResult<T>> => {
        if (pendingError) {
          const err = pendingError;
          pendingError = null;
          return Promise.reject(err);
        }
        if (queue.length) return Promise.resolve({ value: queue.shift()!, done: false });
        if (ended) return Promise.resolve({ value: undefined as unknown as T, done: true });
        return new Promise<IteratorResult<T>>((res) => resolvers.push(res));
      },
      // return(): the loop was `break`/`return`-ed — stop the stream and end cleanly.
      // This is what makes `break` inside `for await` post the `<method>-stop`.
      return: (): Promise<IteratorResult<T>> => {
        sub.stop();
        finish();
        return Promise.resolve({ value: undefined as unknown as T, done: true });
      },
      // throw(): propagate an error into the loop, stopping the stream first.
      throw: (e?: unknown): Promise<IteratorResult<T>> => {
        sub.stop();
        finish();
        return Promise.reject(e);
      },
    };

    return {
      [Symbol.asyncIterator]: () => iterator,
      // Public stop() for callers that hold the iterable directly (not via for-await).
      stop: () => {
        sub.stop();
        finish();
      },
    };
  }

  /* ---------------------------------------------------------------- *
   * handleResponse() — the single inbound router
   * ---------------------------------------------------------------- */

  /**
   * Route one inbound `<method>-response` envelope. This is the ONLY place inbound
   * frames enter the engine (wired to `Transport.onResponse` by index.ts). Routing
   * precedence:
   *   1. matches a pending one-shot `call()` by `payload.ref` → verify → resolve/reject;
   *   2. matches an active `stream()` by `payload.ref` → verify → frame or terminate;
   *   3. matches nothing → forward to `onEvent(type, payload)` (never dropped).
   *
   * Signature verification (INVARIANT #2) happens BEFORE any data is handed out, in
   * both the call and stream branches. A bad signature rejects/ends with ERR_SIGNATURE.
   */
  handleResponse(env: ResponseEnvelope): void {
    const payload = env.payload;
    const ref = payload?.ref;
    // A response with no ref can't be correlated — treat it as an unknown event so it
    // is surfaced rather than silently dropped.
    if (typeof ref !== 'string') {
      this.#onEvent(env.type, payload);
      return;
    }

    // (1) pending one-shot call.
    const pending = this.#pending.get(ref);
    if (pending) {
      // Verify BEFORE resolving. getSession() is read fresh so we check against the
      // key that is current now (handles the connect→session-established transition).
      if (!this.#verify(payload, env.signature)) {
        pending.reject(
          new NinjaError('ERR_SIGNATURE', {
            method: pending.method,
            ref,
            hint: 'response signature failed verification',
          }),
        );
        return;
      }
      // Verified. Success → hand back the payload (or, when the caller asked for
      // the envelope, `{ payload, envelope }` so top-level extras like the
      // connection response's genericUseSeed survive); failure → typed NinjaError.
      //
      // The connection-response is the ONE frame that puts `success` at the
      // ENVELOPE top level (sibling of `payload`), not inside the payload — the
      // parent's connectionHandler.js signs only the payload, so `success` (and
      // the error code) ride outside it. Every other handler nests `success`
      // inside `payload`. So we read the payload's flag first and fall back to the
      // envelope's: without this, a perfectly good connection-response resolves as
      // `payload.success === undefined` → failure → ERR_UNKNOWN.
      // `payload.success` is typed `boolean`, but the connection frame legitimately
      // omits it from the payload (it lives on the envelope), so read it loosely.
      const payloadSuccess = (payload as { success?: unknown }).success;
      const isSuccess = payloadSuccess ?? env.success;
      if (isSuccess) {
        pending.resolve(pending.withEnvelope ? { payload, envelope: env } : payload);
      } else {
        pending.reject(NinjaError.fromPayload(payload, pending.method));
      }
      return;
    }

    // (2) active stream.
    const stream = this.#streams.get(ref);
    if (stream) {
      if (!this.#verify(payload, env.signature)) {
        // A tampered/unsigned frame ends the stream with ERR_SIGNATURE rather than
        // leaking unverified data to the subscriber.
        const err = new NinjaError('ERR_SIGNATURE', {
          method: stream.method,
          ref,
          hint: 'stream frame signature failed verification',
        });
        stream.onError?.(err);
        // Internal stop: the parent didn't necessarily close, but we refuse to
        // continue an unverifiable stream. Post the `-stop` to be safe (not internal).
        this.#streamStoppers.get(ref)?.(false);
        return;
      }
      // A failure responseCode on a stream frame is terminal too (e.g. ERR_ABORTED
      // when the user closes the QR scanner). Surface it and stop.
      if (payload.success === false) {
        const err = NinjaError.fromPayload(payload, stream.method);
        stream.onError?.(err);
        this.#streamStoppers.get(ref)?.(true);
        return;
      }
      // Deliver the frame.
      stream.onFrame(payload);
      // isFinal auto-stops WITHOUT echoing a `-stop` (the parent already ended it).
      if (payload.isFinal === true) {
        this.#streamStoppers.get(ref)?.(true);
      }
      return;
    }

    // (3) unknown — forward, never drop (PROTOCOL.md forward-compat rule #2).
    this.#onEvent(env.type, payload);
  }

  /**
   * Verify a payload's signature against the *current* session key. Centralized so
   * both the call and stream branches use identical, up-to-date session state and so
   * the null-key (pre-connect) semantics live in exactly one place.
   */
  #verify(payload: ResponsePayload, signature: string | undefined): boolean {
    const { pub, version } = this.#getSession();
    return verifyResponse(payload, signature, pub, version);
  }

  /* ---------------------------------------------------------------- *
   * dispose() — tear everything down
   * ---------------------------------------------------------------- */

  /**
   * Tear the engine down: reject every pending `call()` with `ERR_DISCONNECTED`,
   * end every active stream, and clear all timers. Called when the transport is
   * disposed (`ninja.disconnect()`). After this, new calls fail fast.
   *
   * WHY reject-all: a promise that can never resolve is a silent hang in the host app.
   * Disconnecting must surface as a catchable `ERR_DISCONNECTED` on every awaiter.
   */
  dispose(): void {
    if (this.#disposed) return; // idempotent.
    this.#disposed = true;

    // Reject every in-flight call. We snapshot into an array first because reject →
    // settle() mutates #pending mid-iteration.
    for (const [ref, entry] of [...this.#pending]) {
      clearTimeout(entry.timer);
      entry.cleanupAbort?.();
      // Delete before rejecting so any re-entrant handler sees a clean map.
      this.#pending.delete(ref);
      entry.reject(
        new NinjaError('ERR_DISCONNECTED', {
          method: entry.method,
          ref,
          hint: 'transport disposed while awaiting response',
        }),
      );
    }

    // End every active stream. We stop internally (no `-stop` echo — the transport is
    // already gone, so posting would throw) and notify subscribers via onEnd/onError.
    for (const [ref, stream] of [...this.#streams]) {
      stream.active = false;
      const err = new NinjaError('ERR_DISCONNECTED', {
        method: stream.method,
        ref,
        hint: 'transport disposed while streaming',
      });
      // Prefer onError so an AsyncIterable consumer's next pull() rejects; fall back
      // to onEnd for pure-callback subscribers.
      if (stream.onError) stream.onError(err);
      else stream.onEnd?.();
      this.#streams.delete(ref);
      this.#streamStoppers.delete(ref);
    }
  }
}
