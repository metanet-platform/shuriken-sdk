# shuriken-sdk wire protocol

This is the exact protocol `shuriken-sdk` speaks to the Metanet parent window. It is
**frozen and byte-compatible** with the live parent (`metanet_frontend/src/services/appSignaler.js`);
the SDK owns everything above the bytes (correlation, timeouts, verification, streaming, versioning).

The mental model is **JSON-RPC 2.0 over `postMessage`**: `detail.type` is the method,
`detail.ref` is the id, `detail.*` are the params, `payload` is the result, `payload.responseCode` is the error.

## Envelope

| Direction | Field | Value | Notes |
|---|---|---|---|
| both | `command` | `"ninja-app-command"` | constant marker the parent filters on |
| request (app→parent) | `detail.type` | e.g. `"pay"` | the method |
| request | `detail.ref` | `crypto.randomUUID()`, ≤256 chars | correlation id, SDK-minted |
| request | `detail.<params>` | per method | validated locally before send |
| response (parent→app) | `type` | e.g. `"pay-response"` | `<method>` + `-response` |
| response | `payload.ref` | echoed | correlation key |
| response | `payload.success` | boolean | |
| response | `payload.responseCode` | `OK_SUCCESS` \| `ERR_*` \| snake_case | drives `NinjaError.code` |
| response | `payload.timestamp` | `Date.now().toString()` | **string** on the wire; SDK parses |
| response | `payload.isFinal` | boolean | streaming: marks the terminal frame |
| response | `signature` | hex over `sha256(JSON.stringify(payload))` | verified before resolve |
| connection response only | `genericUseSeed`, `icIdentityPackage` | envelope **top level** | OUTSIDE the signed payload; sent on **both V0 and V1** (V1 re-keys the seed with the connection `salt`). The SDK lifts them onto the `ConnectResult`. |

**Request**

```json
{ "command": "ninja-app-command",
  "detail": { "type": "pay", "ref": "b1a7…", "recipients": [{ "address": "1A1z…", "sats": 5000 }] } }
```

**Response**

```json
{ "command": "ninja-app-command",
  "type": "pay-response",
  "payload": { "ref": "b1a7…", "success": true, "responseCode": "OK_SUCCESS", "timestamp": "1751457600000", "rawTxHex": "0100…" },
  "signature": "3045…" }
```

## Correlation & lifecycle

- The SDK mints one `ref` per call and registers `Map<ref, { resolve, reject, timer }>`.
- On an inbound `<method>-response`, it matches `payload.ref`, **verifies the signature**, then resolves — and immediately clears the timer and deletes the map entry (no leaks). Concurrent calls never collide.
- On timeout / `AbortSignal` / transport teardown, the entry is removed and the promise rejects with `ERR_TIMEOUT` / `ERR_DISCONNECTED`.

## Timeouts (defaults, per-command overridable)

| Methods | Default | Why |
|---|---|---|
| `full-transaction`, `token-history`, `geolocation`, bare `connection` | 30s | data reads / immediate answers — a slow response means a dead parent |
| `open-link` | 2 min | consent overlay — the user decides at their own pace |
| `pay`, `create-post`, `generate-proof`, consent-bearing `connection` (identities/proofs requested) | 10 min | user-paced overlays (forms, consent) + first-time Groth16 proving (zkey download + prove can take minutes) |

**Design rule:** a deadline catches a *dead parent*, never the *user*. Commands that
open a platform overlay stay pending while the user interacts — timing them out at
30–60s rejected requests that then succeeded parent-side. All values are overridable
(`connect({ timeoutMs })` globally, `opts.timeoutMs` per call, `ConnectParams.timeoutMs`
for the identity handshake). A response arriving after a timeout is not lost: it is
routed to `ninja.on('<method>-response')` (forward-compat rule 2), so an app can
still observe it.

## Signature verification (version-aware, default-on)

Every response payload is verified before resolving:

- **V0** — verify against `wallet.publicKeyHex` (secp256k1). The parent signs with the root/session key.
- **V1** — verify against `identities.app.pub`. The parent signs with the **app-specific** key.

There is no fallback chain: the version selects exactly one key. An unverifiable payload rejects with `ERR_SIGNATURE` and never surfaces as data.

## ZK proof verification (client-side, default-on)

Beyond the payload signature, any Groth16 **proof envelope** a response carries
(`{ scheme: "metanet-zk-identity-v1", purpose, seedCommitment, proof: { pi_a, pi_b, pi_c }, assetId? }`)
is verified locally before the call resolves:

- The verifier **recomputes** the circuit's single public signal (the Poseidon
  leaf hash binding `canonicalId` → seedCommitment, purpose label, curve tag,
  and the purpose public key) — it never trusts prover-supplied values — then
  runs the BN254 pairing check via the inlined `@noble/curves` (no snarkjs).
- The two Groth16 verification keys (secp256k1 / Ed25519 curve variants) are
  **embedded in the bundle and SHA-256-pinned** to the digests the platform +
  vault enforce. Pin mismatch ⇒ `ERR_VKEY_INTEGRITY` and nothing verifies
  (fail closed).
- `connection` responses: every envelope in `proofs` / per-identity `.proof`
  is verified against `canonicalId` with that purpose entry's `pub`; a failure
  **rejects the connect** with `ERR_PROOF_INVALID` (the payload signature
  already passed, so a bad proof means a tampered or lying source).
  `generate-proof` bundles are verified the same way before resolving.
- Opt-outs (client-side only, never on the wire): `ConnectParams.verifyProofs`,
  `GenerateProofParams.verifyProof` — both default `true`.

## Origin / target

- **Outbound** posts to `window.parent` with targetOrigin `"*"` (the app cannot know the parent's origin ahead of time; the parent enforces its own allow-list).
- **Inbound** is accepted only if `event.origin ∈ allowedOrigins` (prod). `dev: true` relaxes this to `localhost` explicitly and locally.

## Streaming

`geolocation` and `qr-scan` emit multiple `-response` frames sharing one `ref`. The SDK demuxes them into an `AsyncIterable` (or callback) and auto-sends the paired `-stop` message (`geolocation-stop` / `qr-scan-stop`) on `break` / `.stop()` / teardown.

## BSV broadcast (HTTP side-channel, not postMessage)

The parent's `pay` overlay returns a **signed-but-unbroadcast** raw tx: the UTXO
spend is authorized, nothing is on the network. Finalizing is a separate HTTP
step the SDK performs when `pay.bsv`'s `broadcast` option is `true` (the default):

```
POST https://api.metanet.ninja/data/api
Content-Type: application/json
x-pubkey:    <compressed secp256k1 pub of the session genericUseSeed>
x-signature: <DER hex>

{"data":{"action":"broadcastTransactions","raws":["<rawTxHex>"],"params":{"source":"<app>","timestamp":<ms>}}}
```

The signature covers `sha256(body)` — specifically the **ASCII bytes of the hex
digest, truncated to the leftmost 32 bytes** (the backend verifies with
`elliptic`, which truncates a 512-bit message to the curve size). The body sent
must be the byte-identical string that was signed. With `{ broadcast: false }`
the SDK skips this step and returns the authorized `rawTxHex`; finalize later
with `broadcastRawTx(rawTxHex, me.genericUseSeed)`.

## Handshake & versioning (additive, backward-compatible)

On `connect()` the SDK posts `ninja-hello { protocols, sdkVersion, nav? }`. A
negotiation-aware parent replies
`ninja-ready { protocol, capabilities, ledgers, layout?, locale? }`.
Today's parent ignores `ninja-hello`; after `readyTimeout` the SDK takes the
**assume-legacy** path (protocol 0, full command set). Forward-compat rules baked into the
codec:

1. Unknown response fields are preserved on `.raw`, never rejected.
2. Unknown `<type>` responses route to `ninja.on(type)`, never dropped.
3. A frozen app pins `protocols: [0]` and keeps working indefinitely.

### Chrome geometry, nav preferences & locale (v0.2)

- **`ninja-hello.nav`** *(app → parent, advisory)* — `{ bg?, width?, roundedBottom?,
  sideMargins? }`, set via `connect({ nav })`. The parent sanitizes/clamps every field
  (same CSS allowlist as `navbg`; width px or `'full'`; margins clamped) and applies it to
  its nav bar for the lifetime of the app page, reverting automatically when the user
  navigates away. Requests, not commands: legacy parents ignore the whole object.
- **`ninja-ready.layout`** *(parent → app)* — `{ navBottom }`: the MEASURED bottom edge of
  the parent's fixed nav (CSS px from viewport top), taken AFTER applying `nav` prefs.
  Read it as `ninja.layout()`; place your app's top chrome below it instead of hardcoding
  the platform's nav height. Absent (`ninja.layout() === null`) on legacy/pre-layout
  parents — keep a fallback constant.
- **`ninja-layout`** *(parent → app, unsolicited control frame)* —
  `{ command: 'ninja-app-command', type: 'ninja-layout', layout: { navBottom } }`, pushed
  whenever the parent's nav geometry changes. Updates `ninja.layout()` and fires
  `ninja.on('layout', cb)`. Same source/origin gate as every frame; no signature (it is
  presentational geometry established before any session key exists, exactly like
  `ninja-ready`).
- **`ninja-ready.locale`** *(parent → app)* — the user's platform language (i18n code,
  validated `[A-Za-z0-9_-]{2,35}`, e.g. `en`, `pt-BR`). Read as `ninja.locale()`. Replaces
  the deprecated `metanetLang` iframe query param (still appended for older apps): on a
  legacy parent `ninja.locale()` is `null` — fall back to the param.
- **`ninja-locale`** *(parent → app, unsolicited control frame)* —
  `{ command: 'ninja-app-command', type: 'ninja-locale', locale }`, pushed when the user
  switches language mid-session (something the query param never carried). Updates
  `ninja.locale()` and fires `ninja.on('locale', cb)`. Same gating as `ninja-layout`.
