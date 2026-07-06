# AGENTS.md — shuriken-sdk for AI coding agents

You are integrating a web app with the Metanet social network (metanet.page) via `shuriken-sdk`. This is
the closed, complete surface — there are **12 methods, nothing else**. If you
follow the rules below you will be correct on the first try.

## ⚠️ Read first: the two identity versions

`ninja.connect()` returns one of three shapes, discriminated on `version`:

- `{ anonymous: true, canonicalId: null }` — no user connected.
- `{ version: 0, wallet: { publicKeyHex, address, ... }, canonicalId }` — **V0, legacy.** One wallet object; the parent signs responses with the root key.
- `{ version: 1, app: { pub }, bsv?, icp?, kda?, content?, proofs, canonicalId }` — **V1, standard.** Purpose-scoped keys; the parent signs with the **app-specific** key `app.pub`.

The core purposes today are `app`/`bsv`/`icp`/`kda`/`content`. `app` is the always-shared session signer (pub only); `bsv`/`icp`/`kda` carry a chain id-field (`address`/`principal`/`account`); `content` is a pure key purpose (pub only, **no** chain field). Future platform versions may add more purposes, including custom namespaces — the SDK forwards unknown purposes untouched (they surface verbatim on `me` under their own key, and via `me.raw`).

Rules:
1. **Anchor to `me.canonicalId`.** It is the only field present on both versions. Do not key user data on `wallet.address` or `bsv.address`.
2. **Never read `wallet.*` without `if (me.version === 0)`, nor `bsv/icp/kda/content/app` without `if (me.version === 1)`.** TypeScript enforces this; respect it.
3. **No fallback chains.** There is no `wallet || identities`. The version selects exactly one shape. If `version` is missing and `anonymous` is false, that is a bug — surface it, don't guess.

## The API in one rule

Everything is either typed sugar or the uniform core — same round trip underneath:

```ts
await ninja.pay.bsv([{ address, sats: 5000 }]);        // typed sugar (prefer this)
await ninja.call('pay', { recipients: [...] });        // uniform core (equivalent)
```

Use `ninja.call(method, params, opts)` when a method has no sugar yet. Streaming
methods are NOT promises — use the subscription form.

## Task recipes

- **Identify the user:** `const me = await ninja.connect({ request: ['bsv'] })` then branch on `me.anonymous` / `me.version`.
- **Take a BSV payment:** `await ninja.pay.bsv([{ address, sats }])` → `{ txid, rawTxHex, broadcast: true }`. Multi-recipient is allowed; `usd` and `fee` recipients are allowed. Broadcast defaults to **true** (the SDK finalizes on the network). Pass `{ broadcast: false }` to get the authorized-but-unbroadcast `rawTxHex` (nothing on-chain yet); finalize later with `broadcastRawTx(rawTxHex, me.genericUseSeed)`. `broadcast: true` before `connect()` throws `ERR_NO_BROADCAST_KEY`.
- **Take an ICP/KDA payment:** `ninja.pay.icp({ token, to, amount })` / `ninja.pay.kda({ to, amount })`. **Single recipient only** — multiple throws `ERR_MULTIPLE_RECIPIENTS`. ICP `amount` is a **whole-token decimal** (e.g. `1.5`), never base units/bigint. KDA supports **chain `'2'` only** for now — any other `chainId` throws `ERR_NOT_SUPPORTED`.
- **Post to the feed:** `await ninja.feed.createPost({ headline, previewAsset })`. You cannot set the app name; the platform forces it.
- **Prove identity (ZK):** prefer `ninja.connect({ proofs: ['app'] })` to batch consent. Standalone shortcut: `ninja.proof.generate({ reason })` — mints the **app** proof only (no `purpose` param exists). On a V0 user, app proofs throw `app_proof_requires_v1` — fall back to trusting `canonicalId` via the signed connection.
- **Ask for more identities/proofs later:** call `ninja.connect({ request, proofs })` again — it is re-callable and is the canonical incremental-consent pattern. Already-approved items resolve **silently** (no overlay); any NEW item re-prompts the user with the **full** list. Approvals persist across visits; denials are per-visit.
- **Verify a peer's proof:** `ninja.identity.verifyProof(proof, canonicalId)`.
- **Fetch a tx for SPV:** `await ninja.tx.get(txid)` → `{ rawHex, bumpHex }`.
- **Location:** one-shot `await ninja.geo.current()`; stream `for await (const fix of ninja.geo.watch()) { if (fix.isFinal) break; }`. Breaking the loop stops the stream.
- **QR:** `ninja.qr.scan(({ rawValue, parsed }) => {})` — delivers the **first** decoded code then **auto-closes** the camera; keep the returned handle to `.stop()` early (before any scan).
- **Clipboard:** `ninja.clipboard.write(text)` — returns `void`, there is no response, do not `await` a result.
- **Port a legacy bespoke ninja SDK app in one line:** replace the local import with `import client from 'shuriken-sdk/compat'` — identical singleton surface (`connect()`, `payBSV()`, `getBSVHistory()`, `scanQRCode()`, `on/off/once`, same resolved shapes + localStorage keys) on the verified engine; then migrate call sites to the typed API per [docs/MIGRATION.md](./docs/MIGRATION.md).

## Errors

Catch `NinjaError`; branch on `err.code` (a closed union). Common ones:
`ERR_ABORTED` (user cancelled — usually not shown), `ERR_UNSUPPORTED_TOKEN`,
`ERR_MULTIPLE_RECIPIENTS`, `user_denied`, `app_proof_requires_v1`, `invalid_salt`,
`ERR_TIMEOUT` (retriable), `ERR_SIGNATURE` (never trust the payload). Localize with `t(err.code)`.

## Don'ts

- Don't parse `payload.timestamp` as a number without `Number(...)` — it's a string on the wire (the SDK already does this for you).
- Don't expect `write-clipboard` to resolve with data.
- Don't hardcode ICP ledger canister ids — use `ninja.tokens` (e.g. `ninja.tokens.ckUSDC`).
- Don't send more than one recipient to ICP/KDA.
- Don't skip `connect()` — `ninja.connect()` (identity) requires the transport from `connect()` (init). They are different calls; init first.

## Discover at runtime

`ninja.capabilities()` returns the full manifest; `ninja.capabilities('pay')` returns
one method's schema + example. The same data lives in `shuriken-sdk/manifest.json`.
