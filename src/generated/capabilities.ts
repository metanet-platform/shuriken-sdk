/**
 * shuriken-sdk — GENERATED capability snapshot. DO NOT EDIT BY HAND.
 *
 * WHAT: a typed, frozen mirror of the command surface declared in the top-level
 *       `manifest.json`. Produced by `scripts/generate.ts` (`npm run generate`,
 *       and again as the first step of `npm run build`).
 * WHY:  gives the runtime a dependency-free, tree-shakeable list of capability
 *       names (and a few per-command flags) without importing the manifest JSON,
 *       and makes the manifest ↔ `NinjaMethod` correspondence a *compile-time*
 *       guarantee: the `satisfies NinjaMethod[]` below fails `tsc` if the
 *       generated names ever leave the closed method union.
 *
 * Regenerate instead of editing: change `manifest.json`, then `npm run generate`.
 */

import type { NinjaMethod } from '../types';

/** The protocol version this snapshot was generated from (manifest.protocolVersion). */
export const PROTOCOL_VERSION = 1 as const;

/**
 * Every command name declared in the manifest, in declaration order.
 * Typed `readonly NinjaMethod[]` via `satisfies` so a stray/mistyped name here
 * is a typecheck error — the manifest can never advertise a non-`NinjaMethod`.
 */
export const CAPABILITY_NAMES = [
  'connection',
  'pay',
  'create-post',
  'generate-proof',
  'full-transaction',
  'token-history',
  'geolocation',
  'qr-scan',
  'open-link',
  'write-clipboard',
] as const satisfies readonly NinjaMethod[];

/** A ready-made membership set for O(1) `has(method)` checks in the codec/facade. */
export const CAPABILITY_SET: ReadonlySet<NinjaMethod> = new Set(CAPABILITY_NAMES);

/**
 * Per-command runtime flags lifted from the manifest (streaming/noReply/consent/…).
 * The full schema (request/response/errors/examples) stays in `manifest.json`,
 * which the runtime `capabilities()` reads for the rich slice; this is only the
 * subset the transport/codec branch on hot paths.
 */
export const CAPABILITY_META = {
    "connection": {
      "wireType": "connection",
      "responseType": "connection-response",
      "streaming": false,
      "requiresWallet": false,
      "consent": "connection-overlay",
      "since": "1.0.0"
    },
    "pay": {
      "wireType": "pay",
      "responseType": "pay-response",
      "streaming": false,
      "requiresWallet": true,
      "consent": "payment-overlay",
      "since": "1.0.0"
    },
    "create-post": {
      "wireType": "create-post",
      "responseType": "create-post-response",
      "streaming": false,
      "requiresWallet": true,
      "consent": "create-post-overlay",
      "since": "1.0.0"
    },
    "generate-proof": {
      "wireType": "generate-proof",
      "responseType": "generate-proof-response",
      "streaming": false,
      "requiresWallet": true,
      "consent": "proof-overlay",
      "since": "1.0.0"
    },
    "full-transaction": {
      "wireType": "full-transaction",
      "responseType": "full-transaction-response",
      "streaming": false,
      "requiresWallet": false,
      "consent": null,
      "since": "1.0.0"
    },
    "token-history": {
      "wireType": "token-history",
      "responseType": "token-history-response",
      "streaming": false,
      "requiresWallet": false,
      "consent": null,
      "since": "1.0.0"
    },
    "geolocation": {
      "wireType": "geolocation",
      "responseType": "geolocation-response",
      "stopType": "geolocation-stop",
      "streaming": true,
      "requiresWallet": false,
      "consent": "geolocation-permission",
      "since": "1.0.0"
    },
    "qr-scan": {
      "wireType": "qr-scan",
      "responseType": "qr-scan-response",
      "stopType": "qr-scan-stop",
      "streaming": true,
      "requiresWallet": false,
      "consent": "camera-permission",
      "since": "1.0.0"
    },
    "open-link": {
      "wireType": "open-link",
      "responseType": "open-link-response",
      "streaming": false,
      "requiresWallet": false,
      "consent": "external-link-overlay",
      "since": "1.0.0"
    },
    "write-clipboard": {
      "wireType": "write-clipboard",
      "responseType": null,
      "streaming": false,
      "requiresWallet": false,
      "noReply": true,
      "consent": null,
      "since": "1.0.0"
    }
  } as const;
