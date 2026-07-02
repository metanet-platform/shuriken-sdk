/**
 * shuriken-sdk — the typed error taxonomy.
 *
 * WHAT: a single Error subclass carrying a machine-readable `code`, the failing
 *       method, the correlation `ref`, whether it's worth retrying, a human hint,
 *       and a deep link into the docs.
 * WHY:  the hand-copied SDKs collapsed every failure into a generic
 *       "Payment timeout" string, so callers could not branch on cause or
 *       localize messages. Here `code` is a closed union (see types.ts) that maps
 *       straight to the platform's i18n keys: `t(err.code)` renders a localized
 *       message; `err.code === 'ERR_ABORTED'` cleanly detects a user cancel.
 */

import type { NinjaErrorCode, NinjaMethod, ResponsePayload } from './types';

/** Codes that represent a transient condition where a retry may succeed. */
const RETRIABLE: ReadonlySet<NinjaErrorCode> = new Set<NinjaErrorCode>([
  'ERR_TIMEOUT',
  'connection_failed',
  'ERR_ICP_PREP_FAILED',
  'ERR_KDA_PREP_FAILED',
  'ERR_UNKNOWN',
  'ERR_DISCONNECTED',
]);

/** Base docs URL; the fragment matches an anchor in llms.txt / README. */
const DOCS_BASE = 'https://github.com/metanet-platform/shuriken-sdk#';

export interface NinjaErrorInit {
  method?: NinjaMethod | string;
  ref?: string;
  hint?: string;
  /** The raw response payload, when the error came from the wire. */
  payload?: ResponsePayload;
  cause?: unknown;
}

export class NinjaError extends Error {
  /** Machine-readable, localizable code. Branch on this, not on `message`. */
  readonly code: NinjaErrorCode;
  /** The command that failed, when known. */
  readonly method?: NinjaMethod | string;
  /** Correlation id of the failed request. */
  readonly ref?: string;
  /** True if a retry may succeed (timeouts, transient prep failures). */
  readonly retriable: boolean;
  /** A short, actionable hint (e.g. the V0/V1 fallback to use). */
  readonly hint?: string;
  /** Deep link to the docs anchor for this exact code. */
  readonly docsUrl: string;
  /** The raw wire payload, if any. */
  readonly payload?: ResponsePayload;

  constructor(code: NinjaErrorCode, init: NinjaErrorInit = {}) {
    super(init.hint ? `${code}: ${init.hint}` : code, { cause: init.cause });
    this.name = 'NinjaError';
    this.code = code;
    this.method = init.method;
    this.ref = init.ref;
    this.hint = init.hint;
    this.payload = init.payload;
    this.retriable = RETRIABLE.has(code);
    this.docsUrl = DOCS_BASE + code.toLowerCase();
    // Restore the prototype chain for `instanceof` across transpile targets.
    Object.setPrototypeOf(this, NinjaError.prototype);
  }

  /**
   * Build a NinjaError from a failed wire response.
   * The parent puts the reason in `payload.responseCode`.
   */
  static fromPayload(
    payload: ResponsePayload,
    method: NinjaMethod | string,
  ): NinjaError {
    const code = (payload.responseCode as NinjaErrorCode) || 'ERR_UNKNOWN';
    return new NinjaError(code, { method, ref: payload.ref, payload });
  }
}

/** Narrowing helper for consumers: `catch (e) { if (isNinjaError(e)) ... }`. */
export function isNinjaError(e: unknown): e is NinjaError {
  return e instanceof NinjaError;
}
