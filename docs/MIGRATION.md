# Migrating a legacy bespoke ninja SDK onto `shuriken-sdk`

You have a legacy bespoke ninja SDK (one of the ~15 hand-copied variants) that
talks to the Metanet parent with raw `window.parent.postMessage(...)` and a
`window.addEventListener('message', ...)` handler. This guide moves you onto
`shuriken-sdk` **without changing the wire protocol** — the bytes on the
`postMessage` boundary are identical; `shuriken-sdk` just owns everything above them
(correlation, timeouts, signature verification, streaming, the V0/V1 identity
split) so you delete code instead of maintaining it.

> The wire envelope is **frozen and byte-compatible** with the live parent
> (`metanet_frontend/src/services/appSignaler.js`). Migrating is a client-side
> refactor only — the parent does not change and neither does your app's identity
> or history.

---

## 0. The one-line swap: `shuriken-sdk/compat`

If you want the audited engine **today** without touching call sites, use the
drop-in compat layer. It exports the same lazily-initializing singleton your
legacy bespoke ninja SDK did, with identical method names, signatures, resolved shapes,
event semantics (`on`/`off`/`once` receive the whole envelope), and localStorage
keys (`metanet_app_private_key`, `metanet_app_public_key`, `metanet_bsv_address`,
`metanet_principal`):

```diff
- import client from './sdk/legacyNinjaSdk';
+ import client from 'shuriken-sdk/compat';
```

Then delete your local legacy SDK file. Everything else stays as-is.

| Legacy method (compat keeps it) | Behavior on compat | Typed API to migrate to (eventually) |
|---|---|---|
| `connect(options)` | resolves the legacy `connectionData` (both V0 `wallet` and V1 `identities`/`wallets` shapes) | `ninja.connect({ request, proofs, wallets, navbg })` |
| `isUserConnected()` / `getConnectionData()` / `disconnect()` | identical | `useConnection()` / your own state |
| `payBSV(recipients)` | legacy `value`-satoshi recipients, resolves the raw payload (authorize-only, like legacy) | `ninja.pay.bsv([{ address, sats }])` (adds broadcast) |
| `payICP(ledgerId, to, amount, memo)` | identical wire (nested `specification.ledgerId`) | `ninja.pay.icp({ token, to, amount })` |
| `getBSVHistory(opts)` / `getICPTokenHistory(id, opts)` | resolves the raw payload | `ninja.tx.history({ chain, limit, offset })` |
| `getTokenHistory(tokenId, limit)` | deprecated passthrough (array result) | `ninja.tx.history(...)` |
| `authorizeSwap(p)` / `swapBuy(p)` | passthrough via the uniform core (60 s deadline, as legacy) | `ninja.call('authorise-swap', p)` |
| `getFullTransaction(txid)` | resolves `{ txid, rawHex, bumpHex }` | `ninja.tx.get(txid)` |
| `getGeolocation(opts)` / `onGeolocation(cb)` / `stopGeolocation()` | first-fix promise + listener mirror + ref-less stop | `ninja.geo.current()` / `ninja.geo.watch()` |
| `scanQRCode(opts)` / `onQRScanResponse(cb)` / `onQRScanStop(cb)` / `stopQRScan()` | fire-and-forget `{ ref }` + listeners | `ninja.qr.scan(onResult)` |
| `createPost(postData)` | resolves the raw payload | `ninja.feed.createPost({ headline, ... })` |
| `openLink(url)` | resolves `payload.success` (false on decline, like legacy) | `ninja.openLink(url)` |
| `writeClipboard(text)` | ref-less fire-and-forget | `ninja.clipboard.write(text)` |
| `on` / `off` / `once` | identical (callbacks get the ENTIRE envelope) | `ninja.on(type, cb)` |
| `sendCommand` / `onCommand` / `offCommand` (SDKProvider drift) | supported (raw envelope post / wildcard mirror) | `ninja.call(...)` / `ninja.on(...)` |
| `requestCamera` / `captureFrame` / `stopCamera` / `onCameraFrame` / `transcodeVideo` / `onTranscodeProgress` / `authUser` (drift inventions) | **throw `NinjaError('ERR_NOT_SUPPORTED')`** with a hint — these were never platform commands | build in-app (`getUserMedia`, ffmpeg.wasm, your own agent) |

What you gain for free: inbound origin allow-list + parent-source gating,
UUID correlation, per-command timeouts, and signature verification on every
promise-returning call. Two deliberate divergences: rejections carry the legacy
`err.message` **plus** a typed `err.code`/`err.ninjaError`; and standalone
(non-iframe) use throws `ERR_NOT_EMBEDDED` immediately instead of hanging into a
30 s timeout.

The compat layer is a bridge, not a destination — the sections below are the
real migration onto the typed API.

---

## 1. The compat mental model

Your hand-rolled SDK almost certainly does four things by hand. Map each onto the
one `shuriken-sdk` concept that replaces it:

| What your legacy bespoke ninja SDK does by hand | What `shuriken-sdk` does for you | You now write |
|---|---|---|
| `postMessage({ command:'ninja-app-command', detail:{ type, ... } })` | Builds the frozen envelope in one place | `ninja.call(method, params)` |
| A global `message` listener + a `switch (type)` | A correlation map keyed on a per-call `ref` | nothing — `call()` returns a `Promise` |
| A single shared request id / no id at all → responses cross wires | A fresh `crypto.randomUUID()` `ref` per call | nothing — concurrency is safe by construction |
| `if (payload.wallet) … else if (payload.identities) …` | A **discriminated union** on `version` | `if (me.version === 0)` / `if (me.version === 1)` |
| `try { verify(sig) } catch { /* often skipped */ }` | Version-aware secp256k1 verify **before** resolve | nothing — verified or it rejects `ERR_SIGNATURE` |
| `setTimeout(() => reject('timeout'), 30000)` per call | A per-command timeout table | nothing — or `capabilities` / `opts.timeoutMs` |
| `throw new Error('Payment failed')` | A typed `NinjaError` with a localizable `code` | `catch (e) { if (isNinjaError(e)) t(e.code) }` |

The single sentence to internalize:

> **Everything is `await ninja.call(method, params)` underneath.** The typed sugar
> (`ninja.pay.bsv(...)`) is just a thin, well-typed wrapper over that one call.

### Init vs. identity — the one gotcha

Your old file probably had a single `connect()` that both set up the listener AND
resolved the identity. `shuriken-sdk` splits these deliberately:

```js
// 1. INIT: build transport + run the handshake. Returns the `ninja` client.
const ninja = await connect({ allowedOrigins: ['https://metanet.page'] });

// 2. IDENTITY: request the user's identity over that transport.
const me = await ninja.connect({ request: ['bsv'] });
```

`connect()` (module init, imported from the package) is **not**
`ninja.connect()` (the `connection` command). Call init first; then request
identity. This is why the SDK can verify signatures on the identity response —
the transport already exists.

### Forward-compat, for free

Three rules the codec enforces so your migrated app keeps working as the parent
evolves (you do not write any of this):

1. **Unknown response fields** are preserved on `me.raw` / the resolved payload,
   never rejected.
2. **Unknown `<type>-response` frames** route to `ninja.on(type, …)`, never
   dropped.
3. A **frozen app** can pin `connect({ protocols: [0] })` and keep working
   indefinitely against today's non-negotiating parent.

---

## 2. Method mapping table

Every method your hand-rolled SDK sent as `detail.type` maps 1:1 to a `shuriken-sdk`
call. The **wire method is unchanged** — only your call site changes. Prefer the
typed sugar; the uniform `ninja.call(...)` column is the exact equivalent when a
method has no sugar yet or you want the raw form.

| Wire method (`detail.type`) | Old hand-rolled call (typical) | `shuriken-sdk` sugar | Uniform equivalent |
|---|---|---|---|
| `connection` | `send('connection', { request })` | `ninja.connect({ request, proofs, salt, navbg })` | `ninja.call('connection', { … })` |
| `pay` (BSV) | `send('pay', { recipients })` | `ninja.pay.bsv([{ address, sats }])` | `ninja.call('pay', { recipients })` |
| `pay` (ICP) | `send('pay', { token, recipients:[one] })` | `ninja.pay.icp({ token, to, amount })` | `ninja.call('pay', { … })` |
| `pay` (KDA) | `send('pay', { token, recipients:[one] })` | `ninja.pay.kda({ to, amount, chainId })` | `ninja.call('pay', { … })` |
| `create-post` | `send('create-post', { headline })` | `ninja.feed.createPost({ headline, previewAsset })` | `ninja.call('create-post', { … })` |
| `generate-proof` | `send('generate-proof', { reason })` | `ninja.proof.generate({ reason, purpose })` | `ninja.call('generate-proof', { … })` |
| `full-transaction` | `send('full-transaction', { txid })` | `ninja.tx.get(txid)` | `ninja.call('full-transaction', { txid })` |
| `token-history` | `send('token-history', { chain })` | `ninja.tx.history({ chain, limit, offset })` | `ninja.call('token-history', { … })` |
| `open-link` | `send('open-link', { url })` | `ninja.openLink(url)` | `ninja.call('open-link', { url })` |
| `write-clipboard` | `send('write-clipboard', { text })` | `ninja.clipboard.write(text)` | `ninja.call('write-clipboard', { text })` |
| `geolocation` (stream) | `send('geolocation')` + `switch` on frames | `ninja.geo.current()` / `for await (…of ninja.geo.watch())` | `ninja.call('geolocation', …)` (one-shot) |
| `geolocation-stop` | `send('geolocation-stop')` | *automatic* on `break`/`.stop()` | — |
| `qr-scan` (stream) | `send('qr-scan')` + `switch` on frames | `const s = ninja.qr.scan(onResult)` | — |
| `qr-scan-stop` | `send('qr-scan-stop')` | `s.stop()` (or automatic on teardown) | — |

Notes that trip people up during migration:

- **`write-clipboard` has no response.** Your old code may have `await`ed it and
  hung. `ninja.clipboard.write(text)` returns `void` — do **not** await a result.
- **ICP/KDA are single-recipient.** Passing multiple rejects with
  `ERR_MULTIPLE_RECIPIENTS`. BSV is multi-recipient (and supports `usd` amounts
  and `fee` recipients).
- **Streaming methods are not promises.** `geolocation` and `qr-scan` emit
  multiple frames on one `ref`; use the iterator/callback forms. The paired
  `-stop` message is sent for you when you `break` the `for await`, call
  `.stop()`, or `disconnect()`.
- **Never hardcode ICP ledger canister ids.** Replace literal canister ids with
  `tokens.ckUSDC` / `tokens.ICP` / `tokens.ckBTC` (or pass a raw id — `resolveLedger`
  passes it through).

### Identity: the V0/V1 rewrite

This is the change that fixes the most bugs. Replace any `payload.wallet ||
payload.identities` fallback with a **`version` branch**:

```js
// ❌ hand-rolled: mixes shapes, silently wrong on the other version
const addr = me.wallet?.address ?? me.identities?.bsv?.address;

// ✅ shuriken-sdk: the union forces a version check; TS won't let you mix them
if (me.anonymous) {
  // no user connected — canonicalId is null
} else if (me.version === 0) {
  const addr = me.wallet.address;         // root-key signed session
} else if (me.version === 1) {
  const addr = me.bsv?.address;           // app-key signed session
}
```

Always **anchor user data on `me.canonicalId`** — the only field present on both
versions. Do not key storage on `wallet.address` or `bsv.address`; those differ
across versions and re-keys. There is **no fallback chain**: if `version` is
missing and `anonymous` is false, that is a bug to surface, not to paper over.

---

## 3. Unifying storage & timeouts

The hand-copied SDKs each invented their own persistence keys and their own
timeout numbers, so no two behaved the same. `shuriken-sdk` centralizes both.

### Timeouts — one table, per-command, overridable

Your old file likely had a hardcoded `setTimeout(…, 30000)` on every call. Delete
those. `shuriken-sdk` ships the deadlines from `PROTOCOL.md` and applies them per
command:

| Methods | Default |
|---|---|
| `open-link` | 10 s |
| `full-transaction`, `token-history`, `geolocation`, `connection` | 30 s |
| `pay`, `generate-proof` | 60 s |
| anything else | `default` (30 s) |

Override globally at init, or per call:

```js
// Global override (merged over the defaults; unspecified methods keep theirs):
const ninja = await connect({
  allowedOrigins: ['https://metanet.page'],
  timeoutMs: { pay: 90_000, 'full-transaction': 15_000 },
});

// Per-call override + cancellation (replaces bespoke abort flags):
const ac = new AbortController();
await ninja.pay.bsv(recipients, { timeoutMs: 45_000, signal: ac.signal });
// ac.abort() rejects the pending call with ERR_DISCONNECTED and cleans up.
```

On timeout the call rejects with `ERR_TIMEOUT` (which is `retriable: true`) and
the pending entry is removed — no leaked listeners, no zombie promises. The
`connection` command additionally retries internally before falling back to an
anonymous result, so you no longer hand-roll a retry loop.

### Storage — anchor on `canonicalId`, cache capabilities, drop bespoke keys

Migration checklist for anything your old SDK persisted:

1. **Re-key user state on `me.canonicalId`.** If your storage keys were
   `wallet.address` (V0-only) they will not match on a V1 session for the same
   user. `canonicalId` is stable across versions and re-keys — migrate keys to it
   once, on first connect.
2. **Stop persisting the wire envelope / raw responses.** The SDK owns
   correlation; there is nothing durable to keep. Persist your *domain* result
   (e.g. a `postId`, a `rawTxHex` you broadcast), not the transport frames.
3. **Never persist secrets.** The SDK never exposes a private key; do not invent
   a place to store one. Identity lives with the parent/vault, not your app.
4. **Discover capabilities at runtime instead of hardcoding a method list.**
   Replace any local "supported methods" constant with:

   ```js
   ninja.capabilities();          // the manifest slice for every negotiated command
   ninja.capabilities('pay');     // one command's schema + example, or undefined
   ninja.protocol;                // 0 on the assume-legacy path, else the negotiated number
   ```

   This reads the bundled `manifest.json`, filtered to what the current parent
   actually negotiated — so a frozen parent never makes you advertise a
   capability it lacks, and a newer parent's additions appear without a release.

### Errors — one catch, branch on `code`, localize with `t(code)`

Replace every `throw new Error('… failed')` string with a `NinjaError` branch:

```js
import { isNinjaError } from 'shuriken-sdk';

try {
  await ninja.pay.icp({ token: tokens.ckUSDC, to, amount });
} catch (e) {
  if (!isNinjaError(e)) throw e;              // unexpected — rethrow
  if (e.code === 'ERR_ABORTED') return;       // user cancelled — usually silent
  if (e.retriable) scheduleRetry();           // ERR_TIMEOUT, connection_failed, …
  showToast(t(e.code));                        // localized message; never raw English
}
```

`e.code` is a closed union that maps straight to your i18n keys. `e.method`,
`e.ref`, `e.hint`, `e.docsUrl`, and `e.payload` are all populated for debugging
and support — data your hand-rolled string errors threw away.

---

## Done. What you deleted

After migrating you should have removed: the raw `postMessage` calls, the global
`message` listener and its `switch`, your request-id scheme, every hand-rolled
`setTimeout` timeout, the signature-verify code (and any place it was skipped),
the `wallet || identities` fallbacks, and your bespoke error strings. What
remains is `await ninja.call(...)` (or its sugar) and version-checked reads of
`me`. That is the whole point.
