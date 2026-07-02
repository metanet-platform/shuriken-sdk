/**
 * shuriken-sdk — postMessage transport.
 *
 * WHAT: the single low-level bridge to the parent window. It owns exactly one
 *       `window.addEventListener('message', …)` subscription and multiplexes it
 *       to registered callbacks, while gating EVERY inbound message on two
 *       independent checks: (1) it came from OUR parent window
 *       (`event.source === targetWindow`) and (2) its origin passes the injected
 *       origin policy. Outbound, it posts request envelopes to the parent.
 * WHY:  every module above (codec, handshake) needs to send/receive frames, but
 *       none of them should each attach their own global listener, re-implement
 *       the source/origin gate, or know the raw `window` API. Centralizing it
 *       here means the security-critical filtering lives in ONE audited place,
 *       and torn-down listeners can't leak because there is a single owner.
 *
 * The `onResponse` vs `onRaw` split (per BUILD_SPEC) exists because two kinds of
 * inbound traffic share the same window but have different shapes:
 *   - `onResponse` — well-formed `<method>-response` envelopes destined for the
 *     codec's correlation map; pre-filtered by `isResponseEnvelope`.
 *   - `onRaw` — the handshake's `ninja-ready` and any other non-`-response`
 *     control message, which must pass the SAME source/origin gate but is NOT a
 *     response envelope and would otherwise be silently dropped.
 */

import { isResponseEnvelope } from '../protocol/envelope';
import type { RequestEnvelope, ResponseEnvelope } from '../types';

/**
 * Transport — owns the message channel to a single target (parent) window.
 *
 * WHAT: construct with the target window and an origin predicate; then `post`
 *       requests and subscribe via `onResponse` / `onRaw`. Each subscribe call
 *       returns its own unsubscribe function; `dispose()` tears everything down.
 * WHY:  a class (not free functions) lets us hold the shared listener + the set
 *       of callbacks as encapsulated state and guarantee that the underlying
 *       `addEventListener` is attached lazily on first subscription and removed
 *       once, exactly, on dispose — no double-attach, no leak.
 */
export class Transport {
  /** The window we send to and accept messages from (the parent frame). */
  private readonly targetWindow: Window;

  /** Injected inbound-origin gate (see originPolicy.makeOriginPolicy). */
  private readonly isAllowedOrigin: (origin: string) => boolean;

  /**
   * Response-shaped subscribers (codec). Each receives only messages that pass
   * the source/origin gate AND `isResponseEnvelope`.
   * WHY a Set: multiple independent unsubscribes must not disturb each other,
   * and iteration order is irrelevant.
   */
  private readonly responseCbs = new Set<
    (env: ResponseEnvelope, origin: string) => void
  >();

  /**
   * Raw subscribers (handshake). Receive every message that passes the
   * source/origin gate, WITHOUT the `-response` filter.
   */
  private readonly rawCbs = new Set<(data: unknown, origin: string) => void>();

  /**
   * The bound DOM listener, or null when detached.
   * WHY store the bound reference: `removeEventListener` only removes a handler
   * identical to the one added, so we must keep the exact bound function to be
   * able to detach it on dispose.
   */
  private listener: ((event: MessageEvent) => void) | null = null;

  /** True once dispose() runs; makes teardown idempotent and blocks late posts. */
  private disposed = false;

  /**
   * @param targetWindow the parent window (outbound target + inbound source
   *   identity). Injected rather than read from `window.parent` here so tests
   *   and non-iframe hosts can supply a stand-in.
   * @param isAllowedOrigin predicate applied to `event.origin` on every inbound
   *   message; typically the closure from `makeOriginPolicy`.
   */
  constructor(
    targetWindow: Window,
    isAllowedOrigin: (origin: string) => boolean,
  ) {
    this.targetWindow = targetWindow;
    this.isAllowedOrigin = isAllowedOrigin;
  }

  /**
   * post — send a request envelope to the parent.
   *
   * WHAT: `targetWindow.postMessage(env, '*')`.
   * WHY:  we deliberately use targetOrigin `'*'` (not the parent's real origin):
   *       an embedded app genuinely cannot know its parent's origin ahead of
   *       time, and the PARENT enforces its own inbound allow-list. Our security
   *       boundary is on the INBOUND side (`isAllowedOrigin`), never on this
   *       outbound target. Posting after dispose is a no-op so a late-resolving
   *       caller can't hit a torn-down channel.
   */
  post(env: RequestEnvelope): void {
    if (this.disposed) return;
    // Cast to a plain object for the DOM signature; the wire shape is exactly `env`.
    this.targetWindow.postMessage(env, '*');
  }

  /**
   * onResponse — subscribe to well-formed response envelopes.
   *
   * WHAT: registers `cb` and returns an unsubscribe function. `cb` fires only
   *       for messages that (a) originate from `targetWindow`, (b) pass the
   *       origin policy, and (c) satisfy `isResponseEnvelope`.
   * WHY:  the codec only ever cares about correctly-shaped responses; pushing
   *       the `isResponseEnvelope` filter down here keeps the codec's routing
   *       logic clean and ensures malformed/foreign frames never reach it.
   * @returns an idempotent unsubscribe; calling it more than once is harmless.
   */
  onResponse(cb: (env: ResponseEnvelope, origin: string) => void): () => void {
    this.responseCbs.add(cb);
    this.ensureListening();
    return () => {
      this.responseCbs.delete(cb);
    };
  }

  /**
   * onRaw — subscribe to raw, gated messages (no `-response` filter).
   *
   * WHAT: registers `cb` for EVERY message that passes the source/origin gate,
   *       response-shaped or not, and returns an unsubscribe function.
   * WHY:  the handshake's `ninja-ready` is a control message, not a
   *       `<method>-response`, so it would be filtered out by `onResponse`. It
   *       still must be trusted (same source + origin), hence a separate raw
   *       channel that shares the exact same gate but skips the shape filter.
   * @returns an idempotent unsubscribe.
   */
  onRaw(cb: (data: unknown, origin: string) => void): () => void {
    this.rawCbs.add(cb);
    this.ensureListening();
    return () => {
      this.rawCbs.delete(cb);
    };
  }

  /**
   * dispose — detach the DOM listener and drop all subscribers.
   *
   * WHAT: removes the single `message` listener, clears both callback sets, and
   *       flips `disposed` so `post` and re-subscription become inert.
   * WHY:  an iframe app may be unmounted at any time (SPA route change, parent
   *       teardown); leaving a global listener attached would leak the whole
   *       transport (and its closures) and keep processing messages for a dead
   *       session. Made idempotent so double-dispose is safe.
   */
  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.detach();
    this.responseCbs.clear();
    this.rawCbs.clear();
  }

  /**
   * ensureListening — attach the shared DOM listener on first subscription.
   *
   * WHAT: lazily creates and adds the single `message` handler if not already
   *       attached and not disposed.
   * WHY:  we attach lazily (on first subscribe) rather than in the constructor
   *       so a Transport that is built but never used costs nothing, and we
   *       attach at most ONE listener no matter how many callbacks register —
   *       the handler fans out internally.
   */
  private ensureListening(): void {
    if (this.disposed || this.listener) return;

    const handler = (event: MessageEvent): void => {
      // --- Gate 1: identity of the sender window. ---
      // `event.source` is the window that called postMessage. Requiring it to be
      // exactly our target parent means a sibling iframe (an ad, a tracker)
      // cannot impersonate the parent even if it somehow shares the origin.
      if (event.source !== this.targetWindow) return;

      // --- Gate 2: origin allow-list / dev loopback. ---
      // `event.origin` is browser-supplied and unspoofable; the policy decides
      // whether this origin may talk to us at all.
      const origin = event.origin;
      if (!this.isAllowedOrigin(origin)) return;

      const data: unknown = event.data;

      // --- Fan-out A: response-shaped envelopes to the codec. ---
      // Snapshot via [...set] so a callback that unsubscribes (or subscribes)
      // during dispatch cannot mutate the set mid-iteration.
      if (isResponseEnvelope(data)) {
        for (const cb of [...this.responseCbs]) cb(data, origin);
      }

      // --- Fan-out B: raw subscribers see EVERYTHING that passed the gate. ---
      // This intentionally includes response envelopes too: raw is a superset,
      // so a raw listener (e.g. diagnostics) never misses a frame. The handshake
      // simply ignores anything that isn't its `ninja-ready`.
      for (const cb of [...this.rawCbs]) cb(data, origin);
    };

    this.listener = handler;
    // `addEventListener` on the CURRENT global window: inbound `message` events
    // are delivered to the receiving window, regardless of which frame sent them.
    window.addEventListener('message', handler);
  }

  /**
   * detach — remove the DOM listener if present.
   *
   * WHAT: `removeEventListener` with the stored bound handler, then clears it.
   * WHY:  isolated from `dispose` so the removal uses the exact same function
   *       reference we added (a fresh closure would not match and would leak).
   */
  private detach(): void {
    if (this.listener) {
      window.removeEventListener('message', this.listener);
      this.listener = null;
    }
  }
}
