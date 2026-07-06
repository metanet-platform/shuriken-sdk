/**
 * shuriken-sdk — QR scanner (`ninja.qr`).
 *
 * WHAT: `makeQr` builds `{ scan(onResult) }` over the streaming `qr-scan` wire
 *       method.
 * WHY:  the QR scanner is a long-lived camera stream: the parent opens the camera
 *       and emits a `qr-scan-response` frame per decoded code, sharing one ref,
 *       until the app sends `qr-scan-stop`. A callback API (rather than an async
 *       iterable) matches how scanners are used in practice — you register a
 *       handler once and keep the returned `Subscription` to `stop()` the camera
 *       when the view unmounts.
 */

import type { Codec } from '../protocol/codec';
import type { QrScanResult, ResponsePayload, Subscription } from '../types';

/**
 * Build the `ninja.qr` sugar object.
 *
 * WHAT: returns `{ scan }`.
 * WHY:  `scan` delegates to `codec.stream`, adapting the raw `ResponsePayload`
 *       frame to the caller's `QrScanResult` shape. The codec owns frame demuxing
 *       by ref and dispatches `qr-scan-stop` when the returned `Subscription`'s
 *       `stop()` is called (or on teardown), so the parent releases the camera.
 */
export function makeQr(codec: Codec): { scan(onResult: (result: QrScanResult) => void): Subscription } {
  return {
    /**
     * Open the camera QR scanner; deliver the first decoded code, then close.
     *
     * WHAT: registers `onResult` and returns a `Subscription`. On the FIRST
     *       decoded QR code it invokes `onResult({ rawValue, parsed? })` and then
     *       auto-stops the scanner (sends `qr-scan-stop`), matching the expected
     *       "scan a code -> scanner closes" UX.
     * WHY:  the parent keeps the camera open until it receives `qr-scan-stop`
     *       (simpleHandlers.js), so without an explicit stop the camera would stay
     *       on after a successful scan. We stop on the first hit here so every app
     *       gets the right behavior for free. The returned `Subscription.stop()`
     *       stays available and idempotent (call it to cancel before any scan).
     *       We unwrap the value from `payload.scanData` (line 162: `{ rawValue,
     *       parsed? }`), which the parent nests rather than putting at the top level.
     *
     * @param onResult invoked once, with the first decoded `{ rawValue, parsed? }`.
     * @returns the live `Subscription`; `.stop()` cancels the scanner early.
     */
    scan(onResult: (result: QrScanResult) => void): Subscription {
      // `holder.sub` is set synchronously below (before any async frame arrives),
      // so the frame callback can reach the Subscription to stop it after the hit.
      const holder: { sub?: Subscription } = {};
      let delivered = false;
      const sub = codec.stream('qr-scan', {}, (payload: ResponsePayload) => {
        if (delivered) return;
        const scanData = (payload as { scanData?: QrScanResult }).scanData;
        if (!scanData) return; // ignore any frame that carries no decoded value
        delivered = true;
        onResult(scanData);
        // Auto-close the camera after the first successful decode.
        holder.sub?.stop();
      });
      holder.sub = sub;
      return sub;
    },
  };
}
