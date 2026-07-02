/**
 * shuriken-sdk — inbound origin policy.
 *
 * WHAT: a small factory that compiles the caller's `{ allowedOrigins, dev }`
 *       config into a single, hot-path predicate `(origin) => boolean` used by
 *       the transport to accept or drop every inbound `message` event.
 * WHY:  a `postMessage` listener receives events from EVERY frame on the page —
 *       ads, trackers, other embeds, malicious siblings. Without an origin gate,
 *       a hostile frame could forge a `pay-response` and the SDK would resolve
 *       attacker-controlled data as if it came from the parent. The old SDKs
 *       leaned on a silent global `localhost === true` bypass that occasionally
 *       shipped to prod; here the relaxed path is opt-in, explicit, and
 *       localhost-ONLY, and a misconfigured prod policy (no origins, not dev)
 *       fails LOUDLY at construction rather than silently accepting nothing (or,
 *       worse, everything).
 */

/**
 * The hosts we treat as "local development" when `dev: true`.
 *
 * WHAT: exact hostnames (from a parsed URL, so no port/scheme noise) that count
 *       as loopback.
 * WHY:  we match on the parsed `URL.hostname` — never a substring of the raw
 *       origin string — so an attacker cannot smuggle `https://localhost.evil.com`
 *       or `https://evil.com/?x=localhost` past the check. `[::1]` is IPv6
 *       loopback; browsers report the bracketed form in `URL.hostname`.
 */
const LOCAL_HOSTS: ReadonlySet<string> = new Set([
  'localhost',
  '127.0.0.1',
  '[::1]',
]);

/**
 * makeOriginPolicy — compile an inbound-origin allow predicate.
 *
 * WHAT: returns `(origin: string) => boolean`. In dev mode it allows ONLY
 *       loopback origins; in prod it allows only origins present (exactly, after
 *       normalization) in `allowedOrigins`. Constructing a prod policy with no
 *       allowed origins throws immediately — that is a deployment misconfig, not
 *       a runtime condition to swallow.
 * WHY:  we resolve the config into a closure ONCE (normalizing the allow-list up
 *       front) so the per-message check stays a single Set lookup on the message
 *       hot path. Origins are compared by their canonical `new URL(o).origin`
 *       form so that `https://app.metanet.page`, `https://app.metanet.page/`,
 *       and `https://APP.metanet.page` all resolve to one comparable key —
 *       eliminating the trailing-slash / case mismatches that silently broke
 *       origin checks in the hand-copied SDKs.
 *
 * @param opts.allowedOrigins prod allow-list of parent origins (e.g.
 *   `['https://metanet.page']`). Ignored when `dev` is true.
 * @param opts.dev when true, relax to loopback origins only (never ship true).
 * @throws Error when `dev` is falsy and `allowedOrigins` is empty/absent — a
 *   policy that could never accept a legitimate parent is a bug, so we surface
 *   it at construction where the developer will see it.
 * @returns a predicate the transport calls for every inbound message origin.
 */
export function makeOriginPolicy(opts: {
  allowedOrigins?: string[];
  dev?: boolean;
}): (origin: string) => boolean {
  const dev = opts.dev === true;

  // ---- Dev path: loopback only, and only when explicitly opted in. ----
  // We do NOT consult allowedOrigins here: dev mode is deliberately a hard,
  // self-contained "localhost only" rule so a stray dev flag can never widen
  // access to arbitrary prod origins.
  if (dev) {
    return (origin: string): boolean => {
      // A frame with no/opaque origin (sandboxed iframes, some file:// / data:
      // contexts) reports the literal string "null". Never treat that as local.
      if (!origin || origin === 'null') return false;
      const host = safeHostname(origin);
      return host !== null && LOCAL_HOSTS.has(host);
    };
  }

  // ---- Prod path: precompute a normalized allow-set. ----
  // Normalizing to canonical origins here means the per-message check is a plain
  // Set.has — no parsing, no string massaging on the hot path.
  const normalized = new Set<string>();
  for (const raw of opts.allowedOrigins ?? []) {
    const o = safeOrigin(raw);
    // Silently skipping unparseable entries would let a typo'd allow-list ("htp://…")
    // degrade into "allow nothing" at runtime; instead we drop only the bad
    // entry but still fail loudly below if NOTHING valid remains.
    if (o !== null) normalized.add(o);
  }

  // A prod policy that can never say "yes" is always a misconfiguration — fail now.
  if (normalized.size === 0) {
    throw new Error(
      'shuriken-sdk: allowedOrigins is required when dev is not enabled. ' +
        'Pass the parent origin(s), e.g. { allowedOrigins: ["https://metanet.page"] }, ' +
        'or set { dev: true } for localhost development.',
    );
  }

  return (origin: string): boolean => {
    if (!origin || origin === 'null') return false;
    const o = safeOrigin(origin);
    return o !== null && normalized.has(o);
  };
}

/**
 * safeOrigin — parse an origin string to its canonical `URL.origin`, or null.
 *
 * WHAT: `'https://Foo.com/'` -> `'https://foo.com'`; garbage -> `null`.
 * WHY:  centralizes the "canonicalize an origin, never throw" concern so both
 *       the allow-list build and the runtime check compare identical, normalized
 *       keys. Returning null (not throwing) lets callers decide how to treat an
 *       unparseable value in their own context.
 */
function safeOrigin(value: string): string | null {
  try {
    // `new URL(origin).origin` collapses scheme+host+port and lowercases the
    // host, giving a stable comparison key regardless of trailing slash or case.
    return new URL(value).origin;
  } catch {
    return null;
  }
}

/**
 * safeHostname — parse a URL string to its lowercased hostname, or null.
 *
 * WHAT: `'http://LOCALHOST:5173'` -> `'localhost'`; garbage -> `null`.
 * WHY:  the dev-mode loopback check must match on the structural hostname
 *       component alone (ignoring scheme/port) and must never throw on a
 *       malformed origin, so we isolate that parsing here.
 */
function safeHostname(value: string): string | null {
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return null;
  }
}
