/**
 * shuriken-sdk — request correlation ids.
 *
 * WHAT: mints the per-call `ref` (our JSON-RPC `id`) that ties a response frame
 *       back to the pending call that awaits it.
 * WHY:  the codec keys a `Map<ref, pending>` on this value; the parent echoes it
 *       verbatim as `payload.ref`. Collisions or unstable ids would let one
 *       call's response resolve another call's promise — the concurrency bug the
 *       hand-copied SDKs never got right because they reused a single shared id.
 */

/**
 * Mint a fresh, unique correlation ref for a request.
 *
 * WHAT: returns a v4 UUID from the platform crypto (`crypto.randomUUID()`).
 * WHY:  a UUID is (a) globally unique so concurrent in-flight calls never
 *       collide on the codec's ref map, (b) fixed at 36 characters — well under
 *       the wire's ≤256-char cap — and (c) drawn only from `[0-9a-f-]`, which
 *       is a strict subset of the parent's V1 ref sanitizer allow-list
 *       (`/^[A-Za-z0-9._-]{1,64}$/`). So every ref we mint is
 *       "sanitizeV1Ref-safe" by construction and never needs escaping.
 *
 * We use `globalThis.crypto` so this works uniformly in browsers, workers, and
 * Node ≥ 19 (where webcrypto is global) without importing anything — honoring
 * the zero-runtime-deps rule. `crypto.randomUUID` is available in every target
 * this SDK ships to (modern browsers + Node ≥ 19). A cryptographically strong
 * source also means an adversary cannot predict a future ref to pre-craft a
 * forged response — correlation is defense-in-depth alongside signature checks.
 *
 * TODO(v1.0): if a support matrix ever demands a pre-19 Node or a legacy
 * browser without `crypto.randomUUID`, add a `crypto.getRandomValues`-based v4
 * fallback here. Not implemented now because every current target has it and a
 * silent Math.random fallback would weaken the uniqueness guarantee.
 *
 * @returns a 36-char UUIDv4 string, unique per call and sanitizer-safe.
 */
export function newRef(): string {
  return globalThis.crypto.randomUUID();
}
