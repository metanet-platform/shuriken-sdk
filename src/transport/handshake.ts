/**
 * shuriken-sdk — protocol handshake / capability negotiation.
 *
 * WHAT: `negotiate()` performs the additive, backward-compatible opening
 *       handshake with the parent. It posts a `ninja-hello` announcing the
 *       protocol versions we speak and our SDK version, then resolves either
 *       with the parent's `ninja-ready` (a negotiation-aware parent) or, after
 *       `readyTimeout`, with an "assume-legacy" result (protocol 0 + the full
 *       fallback command set).
 * WHY:  the live parent today IGNORES `ninja-hello` — it predates negotiation.
 *       If the SDK blocked on a reply it would hang forever against every
 *       currently-deployed parent. So the handshake is a race: real reply vs a
 *       bounded timer that degrades gracefully to legacy behavior. This lets us
 *       ship capability negotiation NOW without breaking a single existing host,
 *       and lets future parents advertise richer capabilities/ledgers. The whole
 *       promise resolves EXACTLY ONCE and always cleans up its listener + timer,
 *       so there is no leak and no double-settle regardless of which side wins.
 */

import type { Negotiated, NinjaLayout, NinjaMethod } from '../types';
import type { Transport } from './transport';

/**
 * The control-message envelope shape used by the handshake.
 *
 * WHAT: `ninja-hello` (outbound) and `ninja-ready` (inbound) share the frozen
 *       `command: 'ninja-app-command'` marker but carry their own top-level
 *       `type` and a `detail`/body — they are NOT `<method>-response` envelopes.
 * WHY:  the parent filters ALL messages on `command === 'ninja-app-command'`, so
 *       control frames must carry it too; but they are demuxed by their distinct
 *       `type` string, which is why the transport delivers them via `onRaw`
 *       (the response-envelope filter would drop them).
 */
const WIRE_COMMAND = 'ninja-app-command' as const;

/** Outbound: our capability announcement to the parent. */
const HELLO_TYPE = 'ninja-hello' as const;

/** Inbound: a negotiation-aware parent's reply carrying protocol + capabilities. */
const READY_TYPE = 'ninja-ready' as const;

/**
 * Inbound: unsolicited parent push carrying updated chrome geometry.
 *
 * WHAT: `{ command: 'ninja-app-command', type: 'ninja-layout', layout: {...} }`,
 *       posted by the parent whenever its nav bar geometry changes (and once on
 *       observer attach). Not correlated to any request — a control frame, like
 *       `ninja-ready`, delivered via the transport's raw channel.
 * WHY:  the initial geometry rides `ninja-ready`, but the parent's chrome can
 *       change (responsive relayout, future redesigns) while the app is live;
 *       this frame keeps `ninja.layout()` current without re-handshaking.
 */
const LAYOUT_TYPE = 'ninja-layout' as const;

/**
 * Inbound: unsolicited parent push carrying the user's new platform language.
 *
 * WHAT: `{ command: 'ninja-app-command', type: 'ninja-locale', locale: 'el' }`,
 *       posted when the user switches language while the app is open. The
 *       INITIAL locale rides `ninja-ready.locale` — this frame keeps
 *       `ninja.locale()` current. Together they replace the legacy
 *       `metanetLang` iframe query param.
 */
const LOCALE_TYPE = 'ninja-locale' as const;

/**
 * Locale validation: 2-35 chars of letters/digits/hyphen/underscore covers
 * every real i18n tag (`en`, `el`, `pt-BR`, `zh-Hant`) while rejecting
 * anything that could smuggle markup/CSS into an app that interpolates the
 * value. Untrusted input — validated at the boundary like everything else.
 */
const LOCALE_RE = /^[A-Za-z0-9_-]{2,35}$/;

/**
 * Our own package version, echoed in `ninja-hello`.
 *
 * WHAT: a human-readable SDK version string the parent may log or branch on.
 * WHY:  kept here (a leaf module) so the handshake is self-contained and does
 *       not import the public entry point (`index.ts` already defines its own
 *       copy for other purposes). Purely informational — it does not affect
 *       negotiation, which is driven by the numeric `protocols` list.
 */
// TODO(v1.0): inject this from package.json `version` at build time (define
// replacement in tsup) so it can never drift from the published version.
const SDK_VERSION = '0.2.0';

/**
 * How often (ms) the `ninja-hello` is re-posted while waiting for `ninja-ready`.
 *
 * WHY: `postMessage` has no delivery receipt and a parent typically attaches its
 * listener only after the iframe's `load` event — often AFTER our first hello.
 * Re-posting throughout the ready window means a negotiation-aware parent that
 * subscribes late still sees an announcement and can answer. Duplicates are
 * harmless (`finish()` settles once). 400ms gives ~3 shots inside the default
 * 1.5s window without meaningful traffic.
 */
const HELLO_REPOST_INTERVAL = 400;

/**
 * The raw `ninja-ready` payload we expect from a negotiation-aware parent.
 *
 * WHAT: a structural view of the fields we read off `ninja-ready`. Everything is
 *       optional because the parent is a separate codebase and may omit fields;
 *       we defensively default each one.
 * WHY:  typing the untrusted inbound shape as "all optional" forces us to
 *       validate/default at the boundary rather than assume a well-formed reply,
 *       which is exactly the class of bug (trusting the peer's shape) that this
 *       SDK exists to eliminate.
 */
interface NinjaReadyMessage {
  command?: unknown;
  type?: unknown;
  /** Some parents nest under `detail`, others put it at top level; we read both. */
  detail?: {
    protocol?: unknown;
    capabilities?: unknown;
    ledgers?: unknown;
    layout?: unknown;
    locale?: unknown;
  };
  protocol?: unknown;
  capabilities?: unknown;
  ledgers?: unknown;
  layout?: unknown;
  locale?: unknown;
}

/**
 * negotiate — run the `ninja-hello` / `ninja-ready` handshake with a timeout.
 *
 * WHAT: posts `ninja-hello { protocols, sdkVersion }`, then resolves with the
 *       first valid `ninja-ready` seen on the raw channel, or — if none arrives
 *       within `opts.readyTimeout` ms — with an assume-legacy `Negotiated`
 *       (protocol 0, `capabilitiesFallback` as the command set).
 * WHY:  this is the single point that decides "modern parent vs legacy parent"
 *       for the whole session. Resolving (never rejecting) on timeout is
 *       deliberate: a missing reply is the NORMAL case for today's parents, not
 *       an error. The listener and timer are always cleaned up in `finish()` so
 *       the promise settles exactly once and leaves no dangling subscription.
 *
 * @param t the Transport to post through and subscribe to (`onRaw`).
 * @param opts.protocols protocol versions we're willing to speak, in preference
 *   order (e.g. `[1, 0]`); a frozen app pins `[0]`. Advertised in `ninja-hello`.
 * @param opts.readyTimeout ms to wait for `ninja-ready` before assuming legacy.
 * @param opts.capabilitiesFallback the command names to expose when we fall back
 *   to legacy (the full known command set, so a legacy parent stays fully usable).
 * @returns a `Negotiated` describing the agreed protocol, capability set, and
 *   optional ledger list — consumed by `index.ts` to build the `Ninja` object.
 */
export function negotiate(
  t: Transport,
  opts: {
    protocols: number[];
    readyTimeout: number;
    capabilitiesFallback: string[];
    /**
     * App-requested nav chrome (ConnectOptions.nav), forwarded verbatim inside
     * `ninja-hello`. The PARENT owns sanitization/clamping — the SDK does not
     * pre-validate a purely advisory request, so new fields can flow to newer
     * parents without an SDK release. Omitted entirely when the app sets none.
     */
    nav?: object;
  },
): Promise<Negotiated> {
  return new Promise<Negotiated>((resolve) => {
    // Guard against a double-settle: whichever of {ready, timeout} fires first
    // wins, and the loser becomes a no-op. Without this, a `ninja-ready` that
    // races the timer could try to resolve an already-settled promise and, worse,
    // leave the other side's cleanup unrun.
    let settled = false;

    // Assigned below; declared here so `finish()` can clear the timers and the
    // ready-listener regardless of which one triggers settlement.
    let timer: ReturnType<typeof setTimeout> | undefined;
    let helloTimer: ReturnType<typeof setInterval> | undefined;
    let unsubscribe: (() => void) | undefined;

    /**
     * finish — settle once and tear down the timers and the subscription.
     * WHY: single cleanup path so neither a late `ninja-ready` nor a fired timer
     *      can leak a listener/timer or double-resolve.
     */
    const finish = (result: Negotiated): void => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      if (helloTimer !== undefined) clearInterval(helloTimer);
      if (unsubscribe) unsubscribe();
      resolve(result);
    };

    // --- Listen for the parent's reply BEFORE posting hello. ---
    // Subscribing first eliminates the race where a very fast parent replies
    // between our post and our subscribe and we miss the `ninja-ready`.
    unsubscribe = t.onRaw((data: unknown): void => {
      const parsed = parseReady(data);
      if (parsed) finish(parsed);
    });

    // --- Announce ourselves. ---
    // `type` is the control-frame discriminator (`ninja-hello`), NOT a
    // `<method>-response`; the params live in `detail`. A legacy parent simply
    // ignores an unrecognized `type`, which is precisely why the timeout path exists.
    const postHello = (): void => {
      t.post({
        command: WIRE_COMMAND,
        // The request envelope's `type` is normally the constant marker; for the
        // handshake control frame we overload the top-level `type` to the hello
        // discriminator so a negotiation-aware parent can route it. Cast because
        // this is a control frame, not a standard RequestEnvelope method call.
        type: HELLO_TYPE,
        detail: {
          type: HELLO_TYPE,
          // No correlation ref: the handshake is not request/response-correlated;
          // it is a fire-and-listen announcement answered (if at all) by a
          // broadcast `ninja-ready`. Empty string keeps the RequestEnvelope shape valid.
          ref: '',
          protocols: opts.protocols,
          sdkVersion: SDK_VERSION,
          // Advisory nav-chrome request; a nav-aware parent sanitizes + applies
          // it before answering, so ninja-ready's `layout` reflects the result.
          ...(opts.nav !== undefined ? { nav: opts.nav } : {}),
        },
        // The RequestEnvelope type pins `type` to the wire marker and `detail.type`
        // to a NinjaMethod; a control frame legitimately deviates, so we assert the
        // shape here at the single, documented boundary where it happens.
      } as unknown as import('../types').RequestEnvelope);
    };
    postHello();

    // Re-post the hello throughout the ready window: postMessage has no delivery
    // receipt, and a parent that attaches its listener AFTER our first post (the
    // normal case — parents subscribe on iframe `load`) would otherwise never see
    // the announcement. Duplicates are harmless: `finish()` settles once, and a
    // negotiation-aware parent answers each hello with the same `ninja-ready`.
    helloTimer = setInterval(postHello, HELLO_REPOST_INTERVAL);

    // --- Legacy fallback timer. ---
    // If no valid `ninja-ready` arrives in time, assume a pre-negotiation parent:
    // protocol 0 and the full fallback command set, so the app works unchanged.
    timer = setTimeout(() => {
      finish({
        protocol: 0,
        capabilities: new Set<NinjaMethod | string>(opts.capabilitiesFallback),
        // No `ledgers` on legacy: the parent never advertised any, and callers
        // treat "undefined ledgers" as "unknown / ask the parent", not "none".
      });
    }, opts.readyTimeout);
  });
}

/**
 * parseReady — validate + normalize an inbound frame into a `Negotiated`, or null.
 *
 * WHAT: returns a `Negotiated` only when `data` is a genuine `ninja-ready`
 *       control frame (correct `command` + `type`); otherwise null so the raw
 *       listener ignores unrelated traffic (responses, other control frames).
 * WHY:  the raw channel sees EVERYTHING that passed the origin gate, including
 *       ordinary `<method>-response` envelopes. This is the gate that isolates
 *       the one message the handshake cares about, and it defaults every field
 *       so a partially-formed `ninja-ready` still yields a usable session rather
 *       than throwing.
 */
function parseReady(data: unknown): Negotiated | null {
  if (typeof data !== 'object' || data === null) return null;
  const msg = data as NinjaReadyMessage;

  // Must be our marker command AND the ready discriminator; anything else
  // (pay-response, an unknown control frame) is not for us.
  if (msg.command !== WIRE_COMMAND || msg.type !== READY_TYPE) return null;

  // Parents differ on whether the body sits under `detail` or at the top level;
  // read `detail` first, then fall back to top-level fields, so we interoperate
  // with both conventions without a second handshake variant.
  const body = msg.detail ?? msg;

  // protocol: coerce to a finite number; default 1 (a `ninja-ready` implies a
  // negotiation-aware parent, whose baseline is protocol 1).
  const protocol =
    typeof body.protocol === 'number' && Number.isFinite(body.protocol)
      ? body.protocol
      : 1;

  // capabilities: accept an array of strings; anything else -> empty set (the
  // caller's `capabilities()` will then simply expose nothing extra, never crash).
  const capabilities = new Set<NinjaMethod | string>(
    Array.isArray(body.capabilities)
      ? body.capabilities.filter((c): c is string => typeof c === 'string')
      : [],
  );

  // ledgers: optional string list of supported ICP ledger ids/aliases; omit the
  // field entirely when absent so downstream `undefined` means "not advertised".
  const ledgers = Array.isArray(body.ledgers)
    ? body.ledgers.filter((l): l is string => typeof l === 'string')
    : undefined;

  // layout: optional chrome geometry; omit entirely when absent/malformed so
  // downstream `undefined` means "parent did not advertise it" (legacy or
  // pre-layout modern parents), never a fabricated 0.
  const layout = parseLayout(body.layout);

  // locale: optional user language; same omit-when-invalid discipline.
  const locale = parseLocale(body.locale);

  const negotiated: Negotiated = { protocol, capabilities };
  if (ledgers) negotiated.ledgers = ledgers;
  if (layout) negotiated.layout = layout;
  if (locale) negotiated.locale = locale;
  return negotiated;
}

/** parseLocale — validate an untrusted locale value, or null. */
function parseLocale(value: unknown): string | null {
  return typeof value === 'string' && LOCALE_RE.test(value) ? value : null;
}

/**
 * parseLocaleFrame — validate + normalize an inbound `ninja-locale` push, or null.
 * Same boundary discipline and body conventions (detail-nested or top-level)
 * as `parseLayoutFrame`.
 */
export function parseLocaleFrame(data: unknown): string | null {
  if (typeof data !== 'object' || data === null) return null;
  const msg = data as {
    command?: unknown;
    type?: unknown;
    detail?: { locale?: unknown };
    locale?: unknown;
  };
  if (msg.command !== WIRE_COMMAND || msg.type !== LOCALE_TYPE) return null;
  return parseLocale(msg.detail?.locale ?? msg.locale);
}

/**
 * nextLocale — the live locale cell's transition function (validation +
 * change-dedupe), mirroring `nextLayout`: returns the new locale only when
 * `data` is a valid `ninja-locale` push that differs from `current`.
 */
export function nextLocale(current: string | null, data: unknown): string | null {
  const parsed = parseLocaleFrame(data);
  if (!parsed) return null;
  if (parsed === current) return null;
  return parsed;
}

/**
 * parseLayout — validate an untrusted `layout` field into a `NinjaLayout`, or null.
 *
 * WHAT: accepts only `{ navBottom: finite number ≥ 0 }`; anything else -> null.
 * WHY:  the value comes from a separate codebase over postMessage. Defaulting a
 *       malformed field to null (rather than 0) preserves the meaning "unknown —
 *       keep your fallback", so a parent bug can't collapse app chrome to the
 *       viewport top.
 */
function parseLayout(value: unknown): NinjaLayout | null {
  if (typeof value !== 'object' || value === null) return null;
  const navBottom = (value as { navBottom?: unknown }).navBottom;
  if (typeof navBottom !== 'number' || !Number.isFinite(navBottom) || navBottom < 0) {
    return null;
  }
  return { navBottom };
}

/**
 * nextLayout — the live layout cell's transition function.
 *
 * WHAT: given the CURRENT layout (or null) and an arbitrary inbound raw frame,
 *       returns the NEW layout when (and only when) the frame is a valid
 *       `ninja-layout` push that actually changes the value; null otherwise
 *       (not a layout frame, malformed, or a no-op re-announcement).
 * WHY:  extracted from `connect()`'s onRaw wiring so the dedupe rule — apps
 *       only hear `ninja.on('layout')` on real changes, including the
 *       navBottom:0 edge (a falsy-but-valid value) — is a pure, pinned-by-test
 *       function instead of untested closure logic.
 */
export function nextLayout(current: NinjaLayout | null, data: unknown): NinjaLayout | null {
  const parsed = parseLayoutFrame(data);
  if (!parsed) return null;
  if (current !== null && current.navBottom === parsed.navBottom) return null;
  return parsed;
}

/**
 * parseLayoutFrame — validate + normalize an inbound `ninja-layout` push, or null.
 *
 * WHAT: returns the frame's `NinjaLayout` only when `data` is a genuine
 *       `ninja-layout` control frame (correct `command` + `type` + valid body);
 *       otherwise null so the raw listener ignores unrelated traffic.
 * WHY:  same boundary discipline as `parseReady` — the raw channel sees every
 *       gated frame, and this is the single gate that isolates layout pushes.
 *       The body may sit under `detail` or at top level (both parent
 *       conventions exist); we read both, like `parseReady` does.
 */
export function parseLayoutFrame(data: unknown): NinjaLayout | null {
  if (typeof data !== 'object' || data === null) return null;
  const msg = data as {
    command?: unknown;
    type?: unknown;
    detail?: { layout?: unknown };
    layout?: unknown;
  };
  if (msg.command !== WIRE_COMMAND || msg.type !== LAYOUT_TYPE) return null;
  return parseLayout(msg.detail?.layout ?? msg.layout);
}
