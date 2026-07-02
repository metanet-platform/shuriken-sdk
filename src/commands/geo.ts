/**
 * shuriken-sdk — geolocation (`ninja.geo`).
 *
 * WHAT: `makeGeo` builds `{ current(), watch() }` over the streaming
 *       `geolocation` wire method.
 * WHY:  geolocation is a streaming command — the parent emits multiple
 *       `geolocation-response` frames sharing one ref and expects a paired
 *       `geolocation-stop` when the app is done. `current()` is the one-shot
 *       convenience (resolve the first accurate fix, then stop the stream);
 *       `watch()` exposes the raw multi-fix stream as an async iterable so
 *       `for await (const fix of ninja.geo.watch())` works and `break` auto-stops.
 */

import type { Codec } from '../protocol/codec';
import type { GeoFix, ResponsePayload } from '../types';

/**
 * Build the `ninja.geo` sugar object.
 *
 * WHAT: returns `{ current, watch }`.
 * WHY:  both go through `codec.stream` / `codec.streamIterable` so the codec owns
 *       demuxing frames by ref and sending the `geolocation-stop` teardown; the
 *       sugar only shapes the one-shot-vs-stream ergonomics on top.
 */
export function makeGeo(codec: Codec): {
  current(highAccuracy?: boolean): Promise<GeoFix>;
  watch(highAccuracy?: boolean): AsyncIterable<GeoFix> & { stop(): void };
} {
  return {
    /**
     * One-shot: resolve the first accurate fix, then stop the stream.
     *
     * WHAT: opens the geolocation stream and resolves with the first frame the
     *       parent emits (the parent only emits once it has a fix at the required
     *       accuracy — per the manifest, the first accurate <=100m fix).
     * WHY:  most callers want a single position, not a subscription. We build the
     *       promise over `codec.stream` (not a one-shot `call`) because the wire
     *       command is inherently streaming; on the first frame we resolve and
     *       immediately `sub.stop()` so the paired `geolocation-stop` goes out and
     *       the ref is released — no leaked subscription. A `settled` latch guards
     *       against a late frame racing the stop and resolving twice.
     */
    current(highAccuracy = true): Promise<GeoFix> {
      return new Promise<GeoFix>((resolve) => {
        let settled = false;
        // The wire frame is a ResponsePayload carrying the GeoFix fields (the
        // codec's onFrame is typed to the base payload). We narrow it to GeoFix
        // at this trusted boundary — the manifest guarantees latitude/longitude
        // on a geolocation-response frame.
        const sub = codec.stream('geolocation', { highAccuracy }, (payload: ResponsePayload) => {
          if (settled) return;
          settled = true;
          // Stop first so the geolocation-stop is dispatched before we hand
          // control back to the caller; then resolve with the fix.
          sub.stop();
          resolve(payload as unknown as GeoFix);
        });
        // NOTE: the codec owns the failure path — if the parent returns an error
        // frame or the transport is disposed, the codec rejects the underlying
        // ref (which propagates as the stream ending). We intentionally do not add
        // a second error channel here; `stream` never delivers an error payload as
        // a `GeoFix`, so a failed one-shot manifests as the stream simply closing.
        // TODO(v1.0): once codec.stream exposes an onError/onClose hook, wire it to
        // reject `current()` with the terminal ERR_ABORTED/ERR_NOT_SUPPORTED code
        // instead of leaving the promise pending on a hard failure.
      });
    },

    /**
     * Stream fixes until stopped.
     *
     * WHAT: returns an async iterable of `GeoFix` that yields every frame; a
     *       `break` out of the `for await` (or an explicit `.stop()`) sends
     *       `geolocation-stop` and ends iteration.
     * WHY:  delegated straight to `codec.streamIterable`, which already implements
     *       the AsyncIterable + `stop()` contract and the auto-stop-on-break /
     *       auto-stop-on-final semantics. No wrapping needed — the sugar exists
     *       purely to name the method and pin the `GeoFix` element type.
     */
    watch(highAccuracy = true): AsyncIterable<GeoFix> & { stop(): void } {
      return codec.streamIterable<GeoFix>('geolocation', { highAccuracy });
    },
  };
}
