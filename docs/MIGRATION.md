# Migrating a hand-rolled ninja SDK onto `shuriken-sdk`

You have an old, hand-rolled Metanet client (one of the ~15 hand-copied
`metanetSDK.js` variants) that talks to the parent platform with raw
`window.parent.postMessage(...)` and a `window.addEventListener('message', ...)`
handler. This guide converts it, call site by call site, to the typed
`shuriken-sdk` API.

> **The wire protocol does not change.** The bytes on the `postMessage` boundary
> are frozen and byte-compatible with the live parent
> (`metanet_frontend/src/services/appSignaler.js`). Migrating is a **client-side
> refactor only** — the parent is untouched, and so are your app's identity and
> history. You delete transport code; you do not re-key anything.

There is **no compat shim** — you migrate onto the real API. It is a small,
closed surface (12 methods) and the mapping below is mechanical.

---

## 1. The mental model

Your hand-rolled SDK almost certainly does five things by hand. Map each onto the
one `shuriken-sdk` concept that replaces it:

| What your hand-rolled SDK does | What `shuriken-sdk` does for you | You now write |
|---|---|---|
| `postMessage({ command:'ninja-app-command', detail:{ type, ... } })` | Builds the frozen envelope in one place | `ninja.call(method, params)` |
| A global `message` listener + a `switch (type)` | A correlation map keyed on a per-call `ref` | nothing — `call()` returns a `Promise` |
| A single shared request id / no id → responses cross wires | A fresh `crypto.randomUUID()` `ref` per call | nothing — concurrency is safe by construction |
| `if (payload.wallet) … else if (payload.identities) …` | A **discriminated union** on `version` | `if (me.version === 0)` / `if (me.version === 1)` |
| `try { verify(sig) } catch { /* often skipped */ }` | Version-aware secp256k1 verify **before** resolve | nothing — verified or it rejects `ERR_SIGNATURE` |
| `setTimeout(() => reject('timeout'), 30000)` per call | A per-command timeout table | nothing — or `opts.timeoutMs` |
| `throw new Error('Payment failed')` | A typed `NinjaError` with a localizable `code` | `catch (e) { if (isNinjaError(e)) t(e.code) }` |

The single sentence to internalize:

> **Everything is `await ninja.call(method, params)` underneath.** The typed sugar
> (`ninja.pay.bsv(...)`) is a thin, well-typed wrapper over that one call — same
> round trip, same signature check, same errors.

### Init vs. identity — the one gotcha

Your old file probably had a single `connect()` that both installed the listener
AND resolved the identity. `shuriken-sdk` splits these deliberately:

```js
import { connect } from 'shuriken-sdk';

// 1. INIT: build transport + run the handshake. Returns the `ninja` client.
const ninja = await connect({ allowedOrigins: ['https://metanet.page'] });

// 2. IDENTITY: request the user's identity over that transport.
const me = await ninja.connect({ request: ['bsv'] });
```

`connect()` (module init, imported from the package) is **not**
`ninja.connect()` (the `connection` command). Call init first; then request
identity. Splitting them is what lets the SDK verify the signature on the
identity response — the transport already exists when the reply arrives.

---

## 2. Identity: V0 vs V1, and the canonicalId anchor

This is the change that fixes the most bugs, so read it before the method table.

### The two identity versions

Metanet has two identity models, and your old code almost certainly conflated
them with a `payload.wallet || payload.identities` fallback:

- **V0 — a single wallet (legacy).** One root key. Its **anchor** is the pubkey
  and, canonically, the pubkey's `hash160` (the **pkh**). Responses are signed
  with that root key. Shape: `{ version: 0, wallet: { publicKeyHex, address, … }, canonicalId }`.
- **V1 — purpose-scoped keys (standard).** Separate keys per purpose
  (`app`/`bsv`/`icp`/`kda`/`content`). Its **anchor** is the Poseidon
  **seedCommitment** every purpose key derives from. Responses are signed with
  the **app-specific** key (`app.pub`). Shape:
  `{ version: 1, app:{ pub }, bsv?, icp?, kda?, content?, proofs, canonicalId }`.

### `canonicalId` — one self-describing string for both

In **both** versions the app-facing anchor is delivered as a single string,
`me.canonicalId`:

```
canonicalId = groupWithHyphens( base58( versionByte || anchor ) )

  V0:  versionByte = 0x00,  anchor = hash160(pubkey)   (20 bytes → 40-hex pkh)
  V1:  versionByte = 0x01,  anchor = seedCommitment    (32-byte BN254 field)
```

It encodes the **version AND the anchor** in one URL-safe, copy-paste-safe token
(Bitcoin base58 alphabet, 5-char hyphen groups). You never parse it by hand —
decode it:

```js
import { decodeCanonicalId } from 'shuriken-sdk';

const { version, anchorHex, seedCommitment } = decodeCanonicalId(me.canonicalId);
// V0: { version: 0, anchorHex: '<40-hex pkh>' }
// V1: { version: 1, anchorHex: '<64-hex field>', seedCommitment: '<decimal>' }

// In-client sugar (same function):
ninja.identity.decodeCanonicalId(me.canonicalId);
```

> **ALWAYS key user data on `me.canonicalId`.** It is the only field present on
> both versions and it is stable across versions and re-keys. **Never** key
> storage, caches, or server rows on `wallet.address`, `bsv.address`, or
> `bsv.pub` — those differ between V0 and V1 (and across app re-keys) for the
> same human, so they silently split one user into two.

### The rewrite

```js
// ❌ hand-rolled: mixes shapes, silently wrong on the other version
const addr = me.wallet?.address ?? me.identities?.bsv?.address;
const userKey = me.wallet?.address ?? me.identities?.bsv?.address; // splits the user!

// ✅ shuriken-sdk: branch on version; anchor on canonicalId
if (me.anonymous) {
  // no user connected — me.canonicalId is null
} else {
  const userKey = me.canonicalId;                 // the stable anchor, both versions
  const { version, anchorHex } = decodeCanonicalId(me.canonicalId);

  if (me.version === 0) {
    const addr = me.wallet.address;               // V0: root-key session
    // anchorHex === hash160(me.wallet.publicKeyHex) — the pkh
  } else if (me.version === 1) {
    const addr = me.bsv?.address;                 // V1: app-key session
    // anchorHex is the 32-byte seedCommitment; seedCommitment is its decimal form
  }
}
```

There is **no fallback chain**. The `version` field selects exactly one shape;
TypeScript's discriminated union enforces it. If `version` is missing and
`anonymous` is false, that is a bug to **surface**, not to paper over with `||`.

---

## 3. Method mapping table

Every method your hand-rolled SDK sent as `detail.type` maps 1:1 to a
`shuriken-sdk` call. The **wire method is unchanged** — only your call site
changes. Prefer the typed sugar; the uniform `ninja.call(...)` column is the
exact equivalent when a method has no sugar yet or you want the raw form.

| Wire method (`detail.type`) | Old hand-rolled call (typical) | `shuriken-sdk` sugar | Uniform equivalent |
|---|---|---|---|
| `connection` | `send('connection', { request })` | `ninja.connect({ request, proofs, salt, navbg })` | `ninja.call('connection', { … })` |
| `pay` (BSV) | `send('pay', { recipients })` | `ninja.pay.bsv([{ address, sats }])` | `ninja.call('pay', { recipients })` |
| `pay` (ICP) | `send('pay', { token, recipients:[one] })` | `ninja.pay.icp({ token, to, amount })` | `ninja.call('pay', { … })` |
| `pay` (KDA) | `send('pay', { token, recipients:[one] })` | `ninja.pay.kda({ to, amount, chainId })` | `ninja.call('pay', { … })` |
| `create-post` | `send('create-post', { headline })` | `ninja.feed.createPost({ headline, nftDescription, previewAsset })` | `ninja.call('create-post', { … })` |
| `generate-proof` | `send('generate-proof', { reason })` | `ninja.proof.generate({ reason })` — app-proof shortcut; other purposes via `ninja.connect({ proofs })` | `ninja.call('generate-proof', { … })` |
| `full-transaction` | `send('full-transaction', { txid })` | `ninja.tx.get(txid)` | `ninja.call('full-transaction', { txid })` |
| `token-history` | `send('token-history', { chain })` | `ninja.tx.history({ chain, limit, offset })` | `ninja.call('token-history', { … })` |
| `open-link` | `send('open-link', { url })` | `ninja.openLink(url)` | `ninja.call('open-link', { url })` |
| `write-clipboard` | `send('write-clipboard', { text })` | `ninja.clipboard.write(text)` | `ninja.call('write-clipboard', { text })` |
| `geolocation` (stream) | `send('geolocation')` + `switch` on frames | `ninja.geo.current()` / `for await (…of ninja.geo.watch())` | `ninja.call('geolocation', …)` (one-shot) |
| `geolocation-stop` | `send('geolocation-stop')` | *automatic* on `break`/`.stop()` | — |
| `qr-scan` (stream) | `send('qr-scan')` + `switch` on frames | `const s = ninja.qr.scan(onResult)` | — |
| `qr-scan-stop` | `send('qr-scan-stop')` | `s.stop()` (or automatic on teardown) | — |

Things that trip people up during migration:

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
  `ninja.tokens.ckUSDC` / `ninja.tokens.ICP` / `ninja.tokens.ckBTC` (or pass a
  raw id — `resolveLedger` passes it through).
- **BSV broadcast is built in.** `ninja.pay.bsv(...)` defaults to `broadcast: true`
  and finalizes on the network (returning a `txid`), where the legacy copies
  returned an unbroadcast raw tx. Pass `{ broadcast: false }` for the old
  authorize-only behavior, then finalize with
  `broadcastRawTx(rawTxHex, me.genericUseSeed)`.

### Payments — worked examples

```js
// BSV (multi-recipient, broadcasts by default → txid)
const { txid } = await ninja.pay.bsv([
  { address: '1A1z...', sats: 5000, note: 'coffee' },
  { address: '1BvB...', usd: 2.50 },
  { fee: 'APP_GENERIC' },
]);

// ICP (single recipient; amount is WHOLE token units, e.g. 1.5 ckUSDC)
await ninja.pay.icp({ token: ninja.tokens.ckUSDC, to: 'principal-…', amount: 1.5 });

// KDA (single recipient; chain '2' only for now)
await ninja.pay.kda({ to: 'k:abc…', amount: 1.5 });
```

### Feed, transactions, streams, utilities

```js
const { postId } = await ninja.feed.createPost({
  headline: 'gm',                     // short title
  nftDescription: 'hello Metanet',    // the post BODY (required)
  previewAsset: file,                 // optional image File
});

const tx   = await ninja.tx.get(txid);                     // { txid, rawHex, bumpHex } for SPV
const hist = await ninja.tx.history({ chain: 'bsv', limit: 100 });

const fix = await ninja.geo.current();                     // one-shot
for await (const f of ninja.geo.watch()) { if (f.isFinal) break; }  // stream; break => stops

const scan = ninja.qr.scan(({ rawValue }) => { /* first code, then auto-closes */ });
// scan.stop() cancels early

await ninja.openLink('https://example.com');               // consent overlay
ninja.clipboard.write('copied');                            // fire-and-forget (no response)
```

---

## 4. Proofs — verified for you; V0 has none

ZK proofs are **verified locally by the SDK before you ever see them** — a real
Groth16 pairing check against SHA-256-pinned verification keys embedded in the
bundle, not a schema check:

- **Auto-verify on `connect()`.** If the connection response carries proofs
  (`me.proofs`, per-identity `.proof` envelopes), each is verified against
  `me.canonicalId` before the promise resolves. A failure rejects with
  `ERR_PROOF_INVALID` — the payload signature already passed, so a bad proof
  means a tampered or lying source.
- **Auto-verify on `proof.generate()`.** The returned app-proof bundle is
  verified against its own `canonicalId`/`pub` before resolving.
- **Verify a peer's envelope yourself** (from storage, a peer, a server):

  ```js
  import { verifyIdentityProof, verifyProofOrThrow } from 'shuriken-sdk';

  verifyIdentityProof(envelope, me.canonicalId, me.bsv.pub);   // → boolean
  verifyProofOrThrow(envelope, me.canonicalId, me.bsv.pub);    // → throws ERR_PROOF_INVALID
  // in-client sugar: ninja.identity.verifyProof(...) / verifyProofOrThrow(...)
  ```

  `pub` is the purpose public key that **carried** the proof (`me.bsv.pub`,
  `bundle.pub`, …) — the envelope never contains it. A corrupted SDK bundle
  throws `ERR_VKEY_INTEGRITY` (fail closed), never a silent pass.

> **V0 has no ZK proofs.** V0 predates the circuit — there is nothing to verify.
> Requesting an app proof on a V0 user throws `app_proof_requires_v1`. For a V0
> user, trust comes from **(a)** the signed connection response (secp256k1,
> verified by the SDK) and **(b)** the `canonicalId` anchor
> (`decodeCanonicalId` → `{ version: 0, anchorHex }`, the pkh). Branch on
> `me.version`: only reach for proofs when `me.version === 1`.

---

## 5. Storage, timeouts, errors

The hand-copied SDKs each invented their own persistence keys, timeout numbers,
and error strings, so no two behaved the same. `shuriken-sdk` centralizes all
three.

### Storage — anchor on `canonicalId`, drop bespoke keys

1. **Re-key user state on `me.canonicalId`.** If your keys were `wallet.address`
   (V0-only) they will not match a V1 session for the same user. `canonicalId`
   is stable across versions and re-keys — migrate keys to it once, on first
   connect.
2. **Stop persisting the wire envelope / raw responses.** The SDK owns
   correlation; there is nothing durable to keep. Persist your *domain* result
   (a `postId`, a `rawTxHex` you broadcast), not transport frames.
3. **Never persist secrets.** The SDK never exposes a private key; do not invent
   a place to store one. Identity lives with the parent/vault, not your app.
4. **Discover capabilities at runtime** instead of a hardcoded method list:

   ```js
   ninja.capabilities();          // manifest slice for every negotiated command
   ninja.capabilities('pay');     // one command's schema + example, or undefined
   ninja.protocol;                // 0 on the assume-legacy path, else the negotiated number
   ```

### Timeouts — one table, overridable

Delete every hardcoded `setTimeout(…, 30000)`. `shuriken-sdk` ships per-command
deadlines from `PROTOCOL.md` and applies them automatically. Override globally at
init or per call:

```js
const ninja = await connect({
  allowedOrigins: ['https://metanet.page'],
  timeoutMs: { pay: 90_000, 'full-transaction': 15_000 },
});

const ac = new AbortController();
await ninja.pay.bsv(recipients, { timeoutMs: 45_000, signal: ac.signal });
// ac.abort() rejects the pending call and cleans up — no leaked listeners.
```

On timeout the call rejects with `ERR_TIMEOUT` (`retriable: true`) and the
pending entry is removed. No zombie promises.

### Errors — one catch, branch on `code`, localize with `t(code)`

Replace every `throw new Error('… failed')` string with a `NinjaError` branch:

```js
import { isNinjaError } from 'shuriken-sdk';

try {
  await ninja.pay.icp({ token: ninja.tokens.ckUSDC, to, amount });
} catch (e) {
  if (!isNinjaError(e)) throw e;              // unexpected — rethrow
  if (e.code === 'ERR_ABORTED') return;       // user cancelled — usually silent
  if (e.retriable) scheduleRetry();           // ERR_TIMEOUT, connection_failed, …
  showToast(t(e.code));                        // localized; never raw English
}
```

`e.code` is a closed union that maps straight to your i18n keys. `e.method`,
`e.ref`, `e.hint`, `e.docsUrl`, and `e.payload` are all populated for
debugging/support — data your hand-rolled string errors threw away.

---

## 6. Forward-compat, for free

Three rules the codec enforces so your migrated app keeps working as the parent
evolves (you write none of this):

1. **Unknown response fields** are preserved on `me.raw` / the resolved payload,
   never dropped.
2. **Unknown `<type>-response` frames** route to `ninja.on(type, …)`, never
   dropped.
3. A **frozen app** can pin `connect({ protocols: [0] })` and keep working
   indefinitely against today's non-negotiating parent.

The same forward-compat applies to identity: **unknown/future purposes** surface
verbatim on `me` under their own key (and via `me.raw`), and a **future canonicalId
version byte** is a decode you already handle — `decodeCanonicalId` returns the
`version` so your branch is explicit, never a silent guess.

---

## Done. What you deleted

After migrating you should have removed: the raw `postMessage` calls, the global
`message` listener and its `switch`, your request-id scheme, every hand-rolled
`setTimeout` timeout, the signature-verify code (and any place it was skipped),
the `wallet || identities` fallback, the by-hand `canonicalId` parsing, and your
bespoke error strings. What remains is `await ninja.call(...)` (or its sugar),
`version`-checked reads of `me`, and `decodeCanonicalId(me.canonicalId)` for the
anchor. That is the whole point.
