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
     * Open the camera QR scanner and stream decoded results.
     *
     * WHAT: registers `onResult` for every decoded QR frame and returns a
     *       `Subscription`; call `.stop()` to close the camera (sends `qr-scan-stop`).
     * WHY:  we bridge the codec's base-`ResponsePayload` frame to `QrScanResult`
     *       at this single trusted boundary — a `qr-scan-response` frame carries
     *       `rawValue` (+ optional `parsed`) per the manifest, so the cast is safe.
     *       Returning the raw `Subscription` (not re-wrapping) keeps `active`,
     *       auto-stop-on-final, and abort semantics identical to the codec's.
     *
     * @param onResult invoked once per decoded QR code with `{ rawValue, parsed? }`.
     * @returns the live `Subscription`; `.stop()` closes the scanner.
     */
    scan(onResult: (result: QrScanResult) => void): Subscription {
      return codec.stream('qr-scan', {}, (payload: ResponsePayload) => {
        // The parent nests the decoded value under `payload.scanData`
        // (simpleHandlers.js line 162: `{ rawValue, parsed? }`), NOT at the
        // payload's top level. Unwrap it here — the codec has already gated the
        // frame (only a `success: true` frame carries scanData; ERR_NO_DATA /
        // ERR_ABORTED frames terminate the stream via onError, never reaching here),
        // so `scanData` is present on every frame we deliver.
        const scanData = (payload as { scanData?: QrScanResult }).scanData;
        if (scanData) onResult(scanData);
      });
    },
  };
}
