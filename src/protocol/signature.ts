/**
 * shuriken-sdk — response signature verification (the trust boundary).
 *
 * WHAT: the two pure crypto primitives the codec uses to decide whether an
 *       inbound `<method>-response` payload actually came from the connected
 *       Metanet identity — `verifyResponse(...)` (secp256k1 ECDSA verify over
 *       the payload digest) and `sha256Hex(...)` (the exact digest the parent
 *       hashes and signs).
 * WHY:  a `postMessage` boundary is spoofable — any frame on the page can post
 *       a look-alike `pay-response`. The origin allow-list is the first gate;
 *       this signature check is the second, cryptographic gate. The parent
 *       (`metanet_frontend/src/services/apiOutCalls.js#signPayload`) computes
 *       `SHA256(JSON.stringify(payload))` and ECDSA-signs that digest with the
 *       session key, so the SDK must reconstruct the byte-identical digest and
 *       verify against that same key BEFORE a promise ever resolves. There is
 *       deliberately NO key-fallback chain: the identity version selects exactly
 *       one key, and an unverifiable payload is rejected (`ERR_SIGNATURE`)
 *       rather than surfaced as data — the correctness trap that fractured the
 *       hand-copied SDKs.
 *
 * Zero runtime deps beyond the two `@noble/*` packages (inlined at build).
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

/**
 * SHA-256 of a UTF-8 string, returned as lowercase hex.
 *
 * WHAT: hashes `input` as UTF-8 bytes and hex-encodes the 32-byte digest.
 * WHY:  this is the *canonical* message digest for every signed response. The
 *       parent computes `SHA256(JSON.stringify(payload))` and signs it; the SDK
 *       must produce the byte-identical digest to verify. Exposed as a named
 *       helper so the codec, tests, and any debugging tools all hash the exact
 *       same way (never a hand-rolled `crypto.subtle` variant that could drift
 *       on encoding or casing). Runs everywhere `@noble/hashes` runs — browser,
 *       Node, workers — with no Web Crypto async ceremony.
 *
 * @param input the exact string that was signed, i.e. `JSON.stringify(payload)`.
 * @returns lowercase hex of the 32-byte SHA-256 digest (64 hex chars).
 */
export function sha256Hex(input: string): string {
  // `sha256` accepts a string and UTF-8-encodes it internally — exactly the
  // byte sequence the parent hashed. `bytesToHex` yields lowercase hex, matching
  // the parent's `SHA256(...).toString()` output character-for-character.
  return bytesToHex(sha256(input));
}

/**
 * Verify a response payload's signature against the session public key.
 *
 * WHAT: recomputes `sha256(JSON.stringify(payload))` and checks the given hex
 *       ECDSA signature against `sessionPub` on secp256k1. Accepts either a
 *       DER-encoded signature (variable length, ~70–72 bytes → ~140–144 hex,
 *       what the live parent emits via elliptic's `.toDER('hex')`) or a
 *       fixed-length compact/IEEE-P1363 signature (64 bytes → 128 hex).
 * WHY:  this is the single chokepoint the codec calls before resolving any
 *       promise. Centralizing it here means the version→key selection and the
 *       "no signature established yet" case are decided in exactly one place.
 *
 * Semantics (documented because they are load-bearing correctness rules):
 *
 *  - `sessionPub === null` ⇒ return `true`. The connection *establishes* the
 *    key, so the very first message (the `connection-response` itself) has no
 *    prior key to verify against — there is nothing to check yet. This is NOT a
 *    security hole: that first message is still gated by the origin allow-list
 *    (Transport only accepts frames whose `event.origin ∈ allowedOrigins`), and
 *    every *subsequent* command response is verified against the key this
 *    connection-response just handed us. Returning `true` here (rather than
 *    throwing) lets `normalizeConnection` run and populate the session key.
 *
 *  - Missing/blank `signature` while a `sessionPub` exists ⇒ `false`. Once a key
 *    is established, an unsigned payload is not trustworthy; the codec turns a
 *    `false` here into `ERR_SIGNATURE` and the data never surfaces.
 *
 *  - Any parse/verify error ⇒ `false`, never a throw. Malformed hex, a wrong
 *    key, or a tampered payload are all "unverifiable" — one uniform negative
 *    result so the caller has a single failure path (fail-closed).
 *
 * @param payload    the response payload object exactly as received.
 * @param signature  hex signature (DER or compact); may be undefined.
 * @param sessionPub compressed/uncompressed secp256k1 pubkey hex, or `null`
 *                   when no session key is established yet (see above).
 * @param version    identity version (0 or 1). Present for forward-compat: the
 *                   curve is selected per version. Both versions currently use
 *                   secp256k1 (confirmed against the live parent signer).
 * @returns `true` iff the signature verifies (or verification does not yet
 *          apply); `false` on any failure. Never throws.
 */
export function verifyResponse(
  payload: unknown,
  signature: string | undefined,
  sessionPub: string | null,
  version: 0 | 1 | undefined,
): boolean {
  // No key established yet (the connection-response bootstraps it). The origin
  // check in Transport still gates this frame; there is simply no prior key to
  // verify against. Accept so the connection can complete.
  if (sessionPub === null) return true;

  // A session key exists, so a signature is mandatory. A missing/blank one is
  // treated as an unverifiable payload (fail-closed) rather than an exception.
  if (!signature) return false;

  // TODO(v1.0): confirm the exact V1 signing curve against
  // appSignaler.signWalletPayload before v1.0. V0 signs with the root/session
  // secp256k1 key; V1 signs with the per-app hardened key which is ALSO
  // secp256k1 in the current vault implementation. Both branches therefore use
  // secp256k1 today; this switch is where a future V1 curve (e.g. an alt-scheme
  // app key) would be dispatched. `version` is accepted now so the codec wiring
  // never changes when that day comes.
  const curve = selectCurve(version);

  try {
    // Reconstruct the byte-identical digest the parent signed. The parent hashes
    // `JSON.stringify(payload)` (UTF-8) → 32-byte SHA-256, then ECDSA-signs that
    // digest. We verify against the same prehashed digest — noble's `verify`
    // takes the message *hash* directly (its `prehash` option defaults to false),
    // so we must NOT re-hash it here.
    const digestBytes = sha256(JSON.stringify(payload));

    // Parse the signature into canonical 64-byte compact form (r‖s). The live
    // parent emits DER hex (elliptic `.toDER('hex')`); a compact 64-byte
    // (128-hex) signature is also accepted for forward-compat and cross-impl
    // robustness. Whichever encoding it is, `verify` receives the same bytes.
    const sigBytes = parseSignatureBytes(curve, signature);
    if (!sigBytes) return false;

    // Public key hex → bytes (noble accepts 33-byte compressed or 65-byte
    // uncompressed SEC1 keys, matching elliptic's `getPublic(true|false,'hex')`).
    const pubBytes = hexToBytes(strip0x(sessionPub));

    // verify(signature, messageHash, publicKey). All three are Uint8Array in
    // @noble/curves ≥1.9; message is the raw digest (no internal prehash).
    return curve.verify(sigBytes, digestBytes, pubBytes);
  } catch {
    // Malformed hex, bad key encoding, length mismatch — all collapse to a
    // single fail-closed negative so the codec has one uniform ERR_SIGNATURE path.
    return false;
  }
}

/* ------------------------------------------------------------------ *
 * Internals — not exported; keep the module's public surface to the
 * two functions BUILD_SPEC pins.
 * ------------------------------------------------------------------ */

/**
 * Strip an optional `0x`/`0X` prefix from a hex string.
 *
 * WHAT: returns `hex` without a leading `0x`.
 * WHY:  noble's hex decoders reject a `0x` prefix; upstream callers (or a future
 *       signer) may or may not include one. Normalizing here keeps both
 *       `sessionPub` and the signature tolerant of either convention.
 */
function strip0x(hex: string): string {
  return hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
}

/**
 * Select the elliptic curve for a given identity version.
 *
 * WHAT: maps `version` → the noble curve used to verify that version's
 *       responses. Today every version resolves to `secp256k1`.
 * WHY:  isolates the "which curve" decision so `verifyResponse` reads cleanly
 *       and a future V1 curve change is a one-line edit here rather than a
 *       branch tangled into the verify path. See the TODO in `verifyResponse`.
 */
function selectCurve(_version: 0 | 1 | undefined): typeof secp256k1 {
  // Default both V0 and V1 to secp256k1 (the live parent signs both with a
  // secp256k1 key). `_version` is threaded through for the eventual dispatch.
  return secp256k1;
}

/**
 * Parse a hex ECDSA signature into canonical 64-byte compact bytes.
 *
 * WHAT: decodes either DER hex or compact (64-byte) hex into a noble Signature
 *       and returns its compact `r‖s` byte encoding, or `null` if neither parses.
 * WHY:  the live parent uses elliptic's `.toDER('hex')` (DER), but accepting
 *       compact/P1363 too means the SDK keeps verifying if the signer ever swaps
 *       encodings — one fewer brittle coupling across the frozen boundary. We
 *       pick the parse order by shape: a 128-hex-char string that does not start
 *       with the ASN.1 SEQUENCE tag `30` is almost certainly compact, so we try
 *       compact first for those; otherwise DER first. Whichever fails, we try
 *       the other before giving up. Returning bytes (not the Signature object)
 *       matches what `curve.verify` consumes in @noble/curves ≥1.9.
 */
function parseSignatureBytes(
  curve: typeof secp256k1,
  hex: string,
): Uint8Array | null {
  const clean = strip0x(hex);

  // Heuristic: exactly 64 bytes (128 hex chars) and not DER-shaped ⇒ compact.
  // DER signatures begin with the ASN.1 SEQUENCE tag `30`.
  const looksCompact = clean.length === 128 && !clean.startsWith('30');

  const asDer = (): Uint8Array | null => {
    try {
      return curve.Signature.fromBytes(hexToBytes(clean), 'der').toBytes('compact');
    } catch {
      return null;
    }
  };
  const asCompact = (): Uint8Array | null => {
    try {
      return curve.Signature.fromBytes(hexToBytes(clean), 'compact').toBytes('compact');
    } catch {
      return null;
    }
  };

  // Try the likely encoding first, then fall back to the other. Returning the
  // first that parses keeps a single success path for the caller.
  if (looksCompact) return asCompact() ?? asDer();
  return asDer() ?? asCompact();
}
