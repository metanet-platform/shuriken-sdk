<!-- markdownlint-disable MD033 MD041 -->
<div align="center">

# 🥷 shuriken-sdk

**The official SDK for apps on the [Metanet social network](https://metanet.page).** One typed, signature-verifying bridge from any web app embedded in the Metanet social network (metanet.page) to the platform — identity, BSV/ICP/KDA payments, feed posts, ZK proofs, transactions, geolocation, QR.

Works in **React or any JS/TS project**. Zero runtime dependencies.

</div>

---

## Why this exists

A Metanet app runs in a sandboxed `<iframe>`. It talks to the platform by posting messages to the parent window and awaiting a signed reply. Doing that correctly means minting correlation ids, matching responses, timing out, verifying every signature, telling the two identity versions apart, and streaming location/QR without leaking listeners. `shuriken-sdk` does all of it, so your app is three lines:

```ts
import { connect } from 'shuriken-sdk';

const ninja = await connect({ dev: import.meta.env.DEV });   // handshake + verify, once
const me    = await ninja.connect({ request: ['bsv'] });     // who is the user? (identity, normalized)
const { rawTxHex } = await ninja.pay.bsv([{ address: me.bsv?.address, sats: 5000 }]);
```

That's a real, complete payment flow. Everything below is detail you can read when you need it.

---

## Install

```bash
npm i shuriken-sdk           # any JS or TS project
# React hooks live at the 'shuriken-sdk/react' subpath — same package, no extra install
```

- Ships **ESM + CJS** with hand-written **TypeScript types**, so you get autocomplete even in plain JS.
- **Zero runtime dependencies** (crypto is inlined at build time).

---

## The one idea: a hybrid API

There is exactly **one** thing to understand. Every capability is reachable two ways over the *same* verified, correlated core:

| | Looks like | Use it for |
|---|---|---|
| **Typed sugar** (recommended) | `ninja.pay.bsv([...])`, `ninja.connect()` | everyday code — autocompleted, validated locally, results normalized |
| **Uniform core** | `ninja.call('pay', { recipients: [...] })` | power use, forward-compat, or any method a new platform build adds before the SDK types it |

`ninja.pay.bsv(r)` *is* `ninja.call('pay', { recipients: r })`. Same round trip, same signature check, same errors. Pick whichever reads better; they never diverge.

Streaming capabilities (geolocation, QR) use a third shape — a **subscription** — because they emit many results over time:

```ts
for await (const fix of ninja.geo.watch()) { /* ... */ }     // async iterable
const scan = ninja.qr.scan(({ rawValue }) => {});  // fires once, then auto-closes; scan.stop() cancels early
```

---

## Connecting

`connect()` installs the message listener, negotiates the protocol, and verifies every inbound signature. It resolves once the parent is ready (or, against a legacy parent, after a short fallback). Awaiting it **is** your "ready" gate — there's no separate ready event to wait on.

```ts
const ninja = await connect({
  allowedOrigins: ['https://www.metanet.page', 'https://www.metanet.ninja'],
  dev: import.meta.env.DEV,                 // relaxes origin to localhost ONLY (never ship true)
  protocols: [1, 0],                        // preference; frozen apps pass [0]
  timeoutMs: { default: 30_000, pay: 60_000 },
});

ninja.protocol;       // negotiated protocol number
ninja.capabilities;   // Set of methods this parent build supports
```

## Identity — and the one thing to get right

`ninja.connect()` returns the user's identity, **normalized across the two identity versions** and discriminated on `version` so TypeScript stops you from mixing them up:

```ts
const me = await ninja.connect({ request: ['bsv', 'icp', 'content'], proofs: ['app'] });

if (me.anonymous) {
  showLoginNudge();
} else if (me.version === 0) {
  me.wallet.publicKeyHex;        // V0: single wallet object, root-key signed
} else {
  me.bsv?.address;               // V1: purpose-scoped keys, app-key signed
  me.icp?.principal;
  me.content?.pub;               // content: pure key purpose — pub only, no chain address
}

me.canonicalId;                  // the stable user anchor — present on BOTH versions
me.raw;                          // fully-typed escape hatch to every original field
```

> **V0 vs V1 — read this once.** V0 is the legacy identity (a single `wallet`, signed with the root key). V1 is the standard going forward (purpose-scoped `app`/`bsv`/`icp`/`kda`/`content` keys, signed with the **app-specific** key). Build for V1; the SDK normalizes V0 for you and verifies each with the right scheme. The only field guaranteed on both is `canonicalId` — anchor your app to that.

> **Purposes are extensible.** `app`/`bsv`/`icp`/`kda`/`content` are the core set today (`CORE_IDENTITY_PURPOSES`). Future platform versions may add more — including custom namespaces — and the SDK forwards unknown purposes untouched: they surface verbatim on `me` under their own key, and always via `me.raw`. No SDK release required.

### Asking for more later (incremental consent)

`ninja.connect()` is **re-callable** — it is the canonical way to request identities or proofs after the first handshake. Already-approved items resolve **silently** (no overlay); any **new** item re-prompts the user with the full list. Approvals persist across visits; denials are per-visit.

```ts
await ninja.connect({ request: ['bsv'] });                       // first visit: prompts
await ninja.connect({ request: ['bsv'] });                       // later: silent (already approved)
await ninja.connect({ request: ['bsv', 'content'], proofs: ['content'] }); // new items: re-prompts the full list
```

## Payments

```ts
// BSV — one or many recipients; sats, usd, or a platform fee.
// broadcast defaults to TRUE: the user authorizes in the overlay, then the SDK
// finalizes on the network (signs the broadcast-API request with the session's
// genericUseSeed) and resolves the txid.
const { txid, rawTxHex } = await ninja.pay.bsv([
  { address: '1A1z...', sats: 5000, note: 'coffee' },
  { address: '1BvB...', usd: 2.50 },
  { fee: 'APP_GENERIC' },
]);

// Two-step flow: authorize now, broadcast later. UTXOs are signed/authorized
// but NOTHING is on the network until you finalize.
const auth = await ninja.pay.bsv([{ address, sats: 5000 }], { broadcast: false });
// ... inspect / chain / batch ...
import { broadcastRawTx } from 'shuriken-sdk';
await broadcastRawTx(auth.rawTxHex, me.genericUseSeed);   // finalize

// ICP — single recipient, named ledger (see ninja.tokens)
const { transferOutcome } = await ninja.pay.icp({ token: 'ckUSDC', to: 'principal-...', amount: 1.5 });
// ↑ amount is WHOLE token units (a decimal), e.g. 1.5 ckUSDC — not base units/e8s.

// KDA — single recipient. Only chain '2' is supported for now (others throw ERR_NOT_SUPPORTED).
const { requestKey } = await ninja.pay.kda({ to: 'k:abc...', amount: 1.5 });
```

## Feed, proofs, transactions

```ts
const { postId } = await ninja.feed.createPost({ headline: 'gm', previewAsset: file });

// App-identity proof shortcut (app purpose ONLY — no purpose param). For other
// purposes, re-call ninja.connect({ request, proofs }) — the canonical ask-later way.
const proof = await ninja.proof.generate({ reason: 'gate premium' });

const tx   = await ninja.tx.get(txid);                       // { txid, rawHex, bumpHex } for SPV
const hist = await ninja.tx.history({ chain: 'bsv', limit: 100 });
```

## Streams & utilities

```ts
const fix = await ninja.geo.current();                       // one-shot
for await (const f of ninja.geo.watch()) { if (f.isFinal) break; }   // stream; break => stops

await ninja.openLink('https://example.com');                 // consent overlay
ninja.clipboard.write('copied');                             // fire-and-forget (no response)
```

## Errors — typed, localizable

Every failure is a `NinjaError` with a machine-readable `code`. Never string-match; branch on `code`, and localize with your own `t(code)`.

```ts
import { NinjaError } from 'shuriken-sdk';

try {
  await ninja.pay.bsv([{ address, sats: 5000 }]);
} catch (e) {
  if (e instanceof NinjaError) {
    if (e.code === 'ERR_ABORTED') return;    // user cancelled — not an error to surface
    if (e.retriable) retry();
    toast(t(e.code));                        // e.g. 'ERR_UNSUPPORTED_TOKEN'
    console.debug(e.method, e.ref, e.hint, e.docsUrl);
  } else throw e;
}
```

## React

```tsx
import { NinjaProvider, useConnection, usePayment } from 'shuriken-sdk/react';

function App() {
  return <NinjaProvider request={['bsv']} autoConnect><Checkout /></NinjaProvider>;
}

function Checkout() {
  const { me, status } = useConnection();   // 'connecting' | 'connected' | 'anonymous' | 'error'
  const { pay, pending } = usePayment();
  if (status !== 'connected') return null;
  return (
    <button disabled={pending} onClick={() => pay.bsv([{ address: me.bsv?.address, sats: 5000 }])}>
      {pending ? 'Confirm in wallet…' : 'Pay 5000 sats'}
    </button>
  );
}
```

## Migrating a legacy bespoke ninja SDK

Already shipping one of the hand-copied per-app clients? There is a **drop-in compat layer** — swap one import line and keep every call site:

```diff
- import client from './sdk/legacyNinjaSdk';
+ import client from 'shuriken-sdk/compat';
```

Same singleton, same method names and resolved shapes (`connect()`, `payBSV()`, `getBSVHistory()`, `scanQRCode()`, `on/off/once`, …), same localStorage keys — but every round trip now runs on the verified engine (origin allow-list, correlation, per-command timeouts, signature checks). Methods a drifted copy invented that the platform never supported (camera bridge, video transcode, `authUser`) throw a typed `NinjaError('ERR_NOT_SUPPORTED')` with a hint. Full method map + step-by-step: [docs/MIGRATION.md](./docs/MIGRATION.md).

---

## Security model (what the SDK guarantees)

- **Signature-verify-or-reject.** Every inbound response is verified against the session public key *before* the promise resolves. A bad signature rejects with `ERR_SIGNATURE`; it never reaches your code as data.
- **Origin allow-list, no silent bypass.** Inbound messages are accepted only from `allowedOrigins`. `dev: true` relaxes this to localhost *only* and *only* when you opt in.
- **Keys never leave the vault.** The SDK only ever receives *public* material and time-bounded subkeys. Root seeds and private keys stay in the platform's vault worker and never cross the iframe boundary.
- **Consent stays parent-owned.** Payments, posts, proofs, external links, and first-time location all show a platform-rendered consent UI the SDK can neither forge nor suppress.

## For AI agents & tooling

Documentation is a first-class deliverable here:

- **[`manifest.json`](./manifest.json)** — the machine-readable source of truth: every method, its request/response schema, error codes, consent, and streaming flags. All types, validators, and docs are generated from it.
- **[`llms.txt`](./llms.txt)** — a flat, anchored index for LLMs.
- **[`AGENTS.md`](./AGENTS.md)** — a task-oriented playbook (with the V0/V1 trap called out up top).
- **[`PROTOCOL.md`](./PROTOCOL.md)** — the exact wire protocol.
- At runtime, `ninja.capabilities()` returns the live manifest so an agent can discover the API without reading anything.

## Links

- Wire protocol → [PROTOCOL.md](./PROTOCOL.md)
- Migrating a legacy bespoke ninja SDK → [docs/MIGRATION.md](./docs/MIGRATION.md)
- License: MIT
