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
 * Map a raw `geolocation-response` frame to a {@link GeoFix}.
 *
 * WHAT: unwraps the coords from `payload.location.{latitude,longitude,accuracy}`
 *       and lifts `isFinal` + the (stringified) `timestamp` to the flat GeoFix.
 * WHY:  the parent nests the position under `payload.location`
 *       (geolocationHandler.js), NOT at the payload's top level — surfacing the
 *       raw payload as a GeoFix left `fix.latitude`/`fix.longitude` undefined
 *       (the "?, ?" the demo rendered). One trusted boundary does the unwrap.
 */
function toGeoFix(payload: ResponsePayload): GeoFix {
  const loc =
    (payload as { location?: { latitude?: number; longitude?: number; accuracy?: number } }).location ??
    {};
  const fix: GeoFix = {
    latitude: loc.latitude as number,
    longitude: loc.longitude as number,
    timestamp: payload.timestamp !== undefined ? Number(payload.timestamp) : 0,
  };
  if (loc.accuracy !== undefined) fix.accuracy = loc.accuracy;
  if (payload.isFinal !== undefined) fix.isFinal = payload.isFinal;
  return fix;
}

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
          // Skip heartbeat frames that carry no position yet; resolve on the first
          // frame that actually has a `location`.
          if ((payload as { location?: unknown }).location == null) return;
          settled = true;
          // Stop first so the geolocation-stop is dispatched before we hand
          // control back to the caller; then resolve with the unwrapped fix.
          sub.stop();
          resolve(toGeoFix(payload));
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
      // Stream the raw frames and map each to a flat GeoFix (unwrapping
      // `payload.location`). Wrapping the codec's iterable preserves its
      // stop()/auto-stop-on-break contract: breaking the `for await` returns
      // this generator, which returns the underlying iterator (sending
      // `geolocation-stop`); `.stop()` forwards straight through.
      const raw = codec.streamIterable<ResponsePayload>('geolocation', { highAccuracy });
      return {
        stop: () => raw.stop(),
        async *[Symbol.asyncIterator](): AsyncGenerator<GeoFix> {
          for await (const frame of raw) {
            yield toGeoFix(frame);
          }
        },
      };
    },
  };
}
