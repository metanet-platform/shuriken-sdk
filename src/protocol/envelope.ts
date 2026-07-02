/**
 * shuriken-sdk — wire envelope builder + response type guard.
 *
 * WHAT: the pure, dependency-free functions that (a) shape an outbound
 *       `RequestEnvelope` exactly as the live parent expects, and (b) decide at
 *       runtime whether an arbitrary inbound `postMessage` payload is one of our
 *       `<method>-response` envelopes.
 * WHY:  the envelope is FROZEN and byte-compatible with the parent
 *       (`metanet_frontend/src/services/appSignaler.js`). Centralizing its
 *       construction and recognition here means the rest of the SDK (transport,
 *       codec, commands) never re-derives the shape by hand — the exact drift
 *       that broke the ~15 hand-copied SDKs. These functions are the single
 *       chokepoint through which every byte crosses the postMessage boundary.
 */

import {
  WIRE_COMMAND,
  type RequestEnvelope,
  type ResponseEnvelope,
  type NinjaMethod,
} from '../types';

/**
 * Build the outbound request envelope for a call.
 *
 * WHAT: wraps `{ method, ref, params }` into the frozen wire shape
 *       `{ command, type, detail: { type: method, ref, ...params } }`.
 * WHY:  the parent filters every message on `command === WIRE_COMMAND` and reads
 *       the method from `detail.type` and the correlation id from `detail.ref`.
 *       We spread the caller's params LAST-but-under fixed keys so that a stray
 *       `type`/`ref` inside `params` can never shadow the protocol fields — the
 *       method and ref we were given always win. `command` and the top-level
 *       `type` are both the same constant marker: the parent uses `command` to
 *       accept the message and echoes a `<method>-response` `type` on the reply.
 *
 * NOTE: params is spread by value; we never mutate the caller's object. File /
 *       Blob params (e.g. create-post `previewAsset`) survive structured-clone
 *       through postMessage unchanged, so no special handling is needed here.
 *
 * @typeParam P    - the params object shape for this method.
 * @param method   - the wire method (`NinjaMethod`, or a forward-compat string).
 * @param ref      - the correlation id minted by `newRef()` (see correlation.ts).
 * @param params   - method-specific parameters, spread into `detail`.
 * @returns the fully-formed, ready-to-post request envelope.
 */
export function buildRequest<P extends object>(
  method: NinjaMethod | string,
  ref: string,
  params: P,
): RequestEnvelope {
  return {
    command: WIRE_COMMAND,
    // The top-level echo marker. Identical to `command`; the parent replies with
    // `<method>-response` in the response `type`, never reusing this value.
    type: WIRE_COMMAND,
    // Protocol fields (`type`, `ref`) are written AFTER the spread would land, so
    // they are authoritative and a params key named `type`/`ref` cannot override
    // the real method/correlation id.
    detail: { ...(params as Record<string, unknown>), type: method, ref },
  };
}

/**
 * Strict runtime type guard for inbound response envelopes.
 *
 * WHAT: returns true only when `data` is a `{ command, type, payload }` object
 *       where `command === WIRE_COMMAND`, `type` is a string ending in
 *       `-response`, and `payload.ref` is a string. Narrows to `ResponseEnvelope`.
 * WHY:  the SDK shares the `message` event with the whole page — React devtools,
 *       wallet extensions, other iframes and the parent's own chatter all land
 *       on the same handler. This guard is the gate that lets ONLY our response
 *       envelopes through to the codec; anything else (including our own
 *       `ninja-ready` handshake frame, which has no `payload.ref`) is ignored
 *       here and handled on the raw path. Being strict is a correctness AND a
 *       security property: an unrecognized shape must never be treated as a
 *       response and resolve a pending promise with attacker-controlled data.
 *
 * The check is deliberately conservative and self-contained (no destructuring of
 * possibly-absent objects) so it is safe against `null`, primitives, arrays, and
 * hostile objects with throwing getters on unrelated keys.
 *
 * @param data - an arbitrary `MessageEvent.data`.
 * @returns a type predicate narrowing `data` to `ResponseEnvelope`.
 */
export function isResponseEnvelope(data: unknown): data is ResponseEnvelope {
  // Reject non-objects (null, undefined, primitives, functions) up front.
  if (typeof data !== 'object' || data === null) return false;

  const env = data as { command?: unknown; type?: unknown; payload?: unknown };

  // Must carry the frozen command marker — the parent filters on the same key.
  if (env.command !== WIRE_COMMAND) return false;

  // `type` must be a string of the form `<method>-response`. We check the suffix
  // rather than an allow-list so forward-compat response types (unknown methods
  // added parent-side) still route through the codec, per the protocol's rule 2.
  if (typeof env.type !== 'string' || !env.type.endsWith('-response')) {
    return false;
  }

  // `payload` must be a non-null object carrying a string correlation id. The
  // ref is what the codec matches a pending call on; without it the frame is not
  // a correlatable response and must not pass. (Guard against arrays too — an
  // array is `typeof 'object'` but never a valid payload.)
  const payload = env.payload;
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    return false;
  }
  if (typeof (payload as { ref?: unknown }).ref !== 'string') return false;

  return true;
}

/**
 * Extract the base method name from a response `type`.
 *
 * WHAT: maps `'pay-response'` -> `'pay'`, `'connection-response'` -> `'connection'`.
 * WHY:  the codec needs the originating method to build a `NinjaError` with the
 *       right `.method`, to look up per-command timeouts, and to route unknown
 *       responses to `ninja.on(method)`. We strip exactly the trailing
 *       `-response` (not every `-response` substring) so a hypothetical method
 *       that itself contained the token would not be mangled.
 *
 * If the input does not end in `-response` (should not happen once
 * `isResponseEnvelope` has passed) it is returned unchanged, so this is safe to
 * call defensively.
 *
 * @param type - the response envelope `type`, e.g. `'pay-response'`.
 * @returns the base method string, e.g. `'pay'`.
 */
export function responseMethod(type: string): string {
  const SUFFIX = '-response';
  return type.endsWith(SUFFIX) ? type.slice(0, -SUFFIX.length) : type;
}
