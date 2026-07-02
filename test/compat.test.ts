/**
 * shuriken-sdk — compat-layer parity tests.
 *
 * WHAT: drives the `shuriken-sdk/compat` legacy singleton against a fake parent
 *       Window (an auto-responder that speaks the frozen wire protocol and
 *       SIGNS every payload like the live platform does) and asserts that each
 *       major legacy method resolves the EXACT legacy shape — field names are
 *       the strict contract — and that the drifted copies' unsupportable
 *       inventions throw a typed `ERR_NOT_SUPPORTED`.
 * WHY:  the compat layer's entire value proposition is "swap one import line
 *       and nothing observable changes". These tests pin that observable
 *       surface: resolved field names (`bsvAddress`, `rawHex`, `_raw`, …),
 *       localStorage keys, the wire frames posted (legacy `value` recipients,
 *       nested ICP token spec, ref-less stop commands), and the listener
 *       semantics (`on`/`once` receive the ENTIRE envelope).
 *
 * The harness runs under vitest's node environment: we install a fake `window`
 * (self) whose `.parent` is the fake platform window, and a Map-backed
 * `localStorage`. Responses are delivered with `source: parent` and a
 * production platform origin so BOTH inbound gates (engine transport + compat
 * mirror) are exercised for real. Payloads are secp256k1-signed with a test
 * key that doubles as the session key, so the engine's verify-before-resolve
 * path runs for real too (the legacy copies never had that).
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex } from '@noble/hashes/utils';

import { MetanetSDKCompat } from '../src/compat';
import { isNinjaError } from '../src/errors';
import { sha256Hex } from '../src/protocol/signature';

/* ================================================================== *
 * Test signing identity.
 *
 * The parent signs every response payload with this key; the connection
 * response advertises its compressed pub as the session key (V0
 * wallet.publicKeyHex / V1 identities.app.pub), so post-connect responses are
 * verified against it by the engine — exactly the production flow.
 * ================================================================== */

const PRIV = secp256k1.utils.randomPrivateKey();
const PUB = bytesToHex(secp256k1.getPublicKey(PRIV, true));

/** Sign a payload the way the live parent does: DER over sha256(JSON(payload)). */
function signPayload(payload: unknown): string {
  return secp256k1.sign(sha256(JSON.stringify(payload)), PRIV, { lowS: true }).toDERHex();
}

/** A fixed 32-byte generic-use seed (hex), as the parent would mint per app. */
const SEED = 'ab'.repeat(32);

/** The production origin every fake response is delivered from. */
const ORIGIN = 'https://metanet.page';

/* ================================================================== *
 * Fake windows.
 * ================================================================== */

type Handler = (detail: Record<string, any>) => void;

/**
 * The fake PLATFORM (parent) window: records every posted frame and, when an
 * auto-responder is registered for the frame's `detail.type`, invokes it on a
 * macrotask (like a real cross-frame postMessage round trip).
 */
class FakeParentWindow {
  readonly posted: any[] = [];
  readonly handlers = new Map<string, Handler>();

  postMessage(data: any, _targetOrigin: string): void {
    this.posted.push(data);
    const detail = data?.detail;
    const type = detail?.type;
    const handler = typeof type === 'string' ? this.handlers.get(type) : undefined;
    if (handler) setTimeout(() => handler(detail), 0);
  }

  /** Frames posted for one wire method (reads `detail.type`). */
  postedOf(type: string): any[] {
    return this.posted.filter((p) => p?.detail?.type === type);
  }
}

/**
 * The fake APP (self) window: holds the `message` listeners both the engine's
 * Transport and the compat mirror attach, and can deliver a synthetic inbound
 * event carrying `{ data, origin, source }`.
 */
class FakeSelfWindow {
  readonly listeners = new Set<(ev: MessageEvent) => void>();
  parent: FakeParentWindow;

  constructor(parent: FakeParentWindow) {
    this.parent = parent;
  }

  addEventListener(type: string, fn: (ev: MessageEvent) => void): void {
    if (type === 'message') this.listeners.add(fn);
  }

  removeEventListener(type: string, fn: (ev: MessageEvent) => void): void {
    if (type === 'message') this.listeners.delete(fn);
  }

  /** Deliver an inbound platform frame (source defaults to the parent). */
  deliver(data: unknown, origin: string = ORIGIN, source: unknown = this.parent): void {
    const ev = { data, origin, source } as unknown as MessageEvent;
    for (const fn of [...this.listeners]) fn(ev);
  }
}

/* ================================================================== *
 * Per-test environment.
 * ================================================================== */

let parent: FakeParentWindow;
let self_: FakeSelfWindow;
let sdk: MetanetSDKCompat;
const lsStore = new Map<string, string>();

/** Deliver a SIGNED `<type>-response` envelope (plus top-level extras). */
function respond(type: string, payload: Record<string, unknown>, extras: Record<string, unknown> = {}): void {
  self_.deliver({
    command: 'ninja-app-command',
    type,
    payload,
    signature: signPayload(payload),
    ...extras,
  });
}

/** Register the standard V0 connection auto-responder on the fake parent. */
function installV0Connection(): void {
  parent.handlers.set('connection', (detail) => {
    const payload = {
      ref: detail.ref,
      success: true,
      responseCode: 'OK_SUCCESS',
      appId: 'app-under-test',
      timestamp: '1720000000000',
      anonymous: false,
      version: 0,
      canonicalId: 'canon-v0',
      wallet: {
        address: '1LegacyAddr',
        publicKeyHex: PUB, // the session key the engine verifies against
        rootPrincipal: 'principal-v0',
        canonicalId: 'canon-v0',
      },
      icDelegation: { chain: ['delegation-entry'] },
    };
    respond('connection-response', payload, {
      genericUseSeed: SEED,
      appPageSchema: { theme: 'dark' },
      icIdentityPackage: { privateKey: 'ic-delegation-priv' },
    });
  });
}

beforeEach(() => {
  parent = new FakeParentWindow();
  self_ = new FakeSelfWindow(parent);
  lsStore.clear();
  // Install the fake browser globals the SDK reaches for. The compat layer is
  // lazy, so ordering (globals first, construct after) mirrors a real app.
  (globalThis as any).window = self_;
  (globalThis as any).localStorage = {
    getItem: (k: string) => lsStore.get(k) ?? null,
    setItem: (k: string, v: string) => void lsStore.set(k, String(v)),
    removeItem: (k: string) => void lsStore.delete(k),
    clear: () => lsStore.clear(),
  };
  // readyTimeout 5ms: the fake parent (like the live one) ignores ninja-hello,
  // so the engine takes the assume-legacy path fast instead of waiting 1.5s.
  sdk = new MetanetSDKCompat({ readyTimeout: 5 });
});

afterEach(() => {
  delete (globalThis as any).window;
  delete (globalThis as any).localStorage;
});

/* ================================================================== *
 * connect() — the legacy connectionData shape (V0 and V1).
 * ================================================================== */

describe('compat connect()', () => {
  it('resolves the legacy V0 connectionData shape, field for field', async () => {
    installV0Connection();

    const data = await sdk.connect();

    // The strict legacy field contract.
    expect(data.appId).toBe('app-under-test');
    expect(data.timestamp).toBe('1720000000000');
    expect(data.anonymous).toBe(false);
    expect(data.version).toBe(0);
    expect(data.canonicalId).toBe('canon-v0');
    expect(data.pubHex).toBe(PUB); // falls back to wallet.publicKeyHex on V0
    // V0 wallet-derived fields.
    expect(data.bsvAddress).toBe('1LegacyAddr');
    expect(data.bsvPublicKey).toBe(PUB);
    expect(data.rootPrincipal).toBe('principal-v0');
    // V1 fields are null on V0 — exactly like the legacy copy.
    expect(data.identities).toBeNull();
    expect(data.wallets).toBeNull();
    // Envelope-level extras.
    expect(data.icDelegation).toEqual({ chain: ['delegation-entry'] });
    expect(data.icDelegationPrivateKey).toBe('ic-delegation-priv');
    expect(data.genericUseSeed).toBe(SEED);
    expect(typeof data.signature).toBe('string');
    expect(data.appPageSchema).toEqual({ theme: 'dark' });
    // _raw is the ENTIRE envelope (event.data), not just the payload.
    expect((data._raw as any).command).toBe('ninja-app-command');
    expect((data._raw as any).type).toBe('connection-response');
    expect((data._raw as any).genericUseSeed).toBe(SEED);

    // Singleton state flags (legacy parity).
    expect(sdk.isUserConnected()).toBe(true);
    expect(sdk.getConnectionData()).toBe(data);
  });

  it('persists the legacy localStorage keys (same names, same derivations)', async () => {
    installV0Connection();
    await sdk.connect();

    expect(lsStore.get('metanet_app_private_key')).toBe(SEED);
    // Legacy derived the "public key" as SHA256 of the seed STRING (CryptoJS
    // hex output) — sha256Hex reproduces that byte-for-byte.
    expect(lsStore.get('metanet_app_public_key')).toBe(sha256Hex(SEED));
    expect(lsStore.get('metanet_bsv_address')).toBe('1LegacyAddr');
    expect(lsStore.get('metanet_principal')).toBe('principal-v0');
  });

  it('resolves the legacy V1 shape (identities + wallets pass through untouched) and sends the V1 declaration block on the wire', async () => {
    const identitiesPayload = {
      canonicalId: 'canon-v1',
      app: { purpose: 'app', pub: PUB, appId: 'app-under-test', canonicalId: 'canon-v1' },
      bsv: { purpose: 'bsv', pub: '02bbccdd', address: '1V1BsvAddr', canonicalId: 'canon-v1' },
    };
    const walletsPayload = [{ chain: 'bsv', address: '1V1BsvAddr', pub: '02bbccdd' }];
    parent.handlers.set('connection', (detail) => {
      const payload = {
        ref: detail.ref,
        success: true,
        responseCode: 'OK_SUCCESS',
        appId: 'app-under-test',
        timestamp: '1720000000001',
        anonymous: false,
        version: 1,
        canonicalId: 'canon-v1',
        pubHex: PUB, // V1: the app-namespaced pub
        identities: identitiesPayload,
        wallets: walletsPayload,
      };
      respond('connection-response', payload, { genericUseSeed: SEED });
    });

    const data = await sdk.connect({
      identities: { bsv: { proof: true } },
      appIdentity: { proof: true },
      wallets: ['bsv'],
      navbg: '#101010',
    });

    // Wire assertion: the V1 declaration block reaches the parent unchanged.
    const connFrame = parent.postedOf('connection')[0];
    expect(connFrame.detail.identities).toEqual({ bsv: { proof: true } });
    expect(connFrame.detail.appIdentity).toEqual({ proof: true });
    expect(connFrame.detail.wallets).toEqual(['bsv']);
    expect(connFrame.detail.navbg).toBe('#101010');

    // Resolved legacy V1 shape.
    expect(data.version).toBe(1);
    expect(data.canonicalId).toBe('canon-v1');
    expect(data.pubHex).toBe(PUB);
    expect(data.identities).toEqual(identitiesPayload); // pass-through, untouched
    expect(data.wallets).toEqual(walletsPayload);
    // V0 wallet fields are undefined on V1 — legacy parity.
    expect(data.bsvAddress).toBeUndefined();
    expect(data.bsvPublicKey).toBeUndefined();
    expect(data.rootPrincipal).toBeUndefined();
    // No wallet block ⇒ the V0-only localStorage keys are NOT written.
    expect(lsStore.has('metanet_bsv_address')).toBe(false);
    expect(lsStore.get('metanet_app_private_key')).toBe(SEED);
  });

  it('disconnect() clears state and the persisted keys', async () => {
    installV0Connection();
    await sdk.connect();
    sdk.disconnect();

    expect(sdk.isUserConnected()).toBe(false);
    expect(sdk.getConnectionData()).toBeNull();
    expect(lsStore.has('metanet_app_private_key')).toBe(false);
    expect(lsStore.has('metanet_app_public_key')).toBe(false);
    expect(lsStore.has('metanet_bsv_address')).toBe(false);
    expect(lsStore.has('metanet_principal')).toBe(false);
  });
});

/* ================================================================== *
 * Payments — legacy wire params (value/reason/note, nested ICP spec) and
 * raw-payload resolution, over a signature-verified session.
 * ================================================================== */

describe('compat payments', () => {
  beforeEach(async () => {
    installV0Connection();
    await sdk.connect(); // establishes the session key → responses must verify
  });

  it('payBSV sends legacy recipients verbatim and resolves the raw payload', async () => {
    parent.handlers.set('pay', (detail) => {
      respond('pay-response', {
        ref: detail.ref,
        success: true,
        responseCode: 'OK_SUCCESS',
        txid: 'txid-123',
        rawtx: '0100beef',
      });
    });

    const recipients = [{ address: '1Dest', value: 5000, reason: 'coffee', note: 'thanks' }];
    const result = await sdk.payBSV(recipients);

    // Wire: the legacy field names (value, reason, note) are NOT remapped.
    const frame = parent.postedOf('pay')[0];
    expect(frame.command).toBe('ninja-app-command');
    expect(frame.detail.recipients).toEqual(recipients);

    // Resolved: the raw wire payload, exactly as legacy resolved it.
    expect(result.success).toBe(true);
    expect(result.txid).toBe('txid-123');
    expect(result.rawtx).toBe('0100beef');
    expect(typeof result.ref).toBe('string');
  });

  it('payBSV rejects with the legacy message (payload.error) plus a typed .code', async () => {
    parent.handlers.set('pay', (detail) => {
      respond('pay-response', {
        ref: detail.ref,
        success: false,
        responseCode: 'ERR_ABORTED',
        error: 'User cancelled the payment',
      });
    });

    await expect(sdk.payBSV([{ address: '1Dest', value: 1 }])).rejects.toMatchObject({
      message: 'User cancelled the payment', // legacy: Error(payload.error)
      code: 'ERR_ABORTED', // compat bonus: the typed code rides along
    });
  });

  it('payBSV rejects with the legacy timeout message when nothing answers', async () => {
    // No 'pay' handler registered; shrink the deadline so the test stays fast.
    const fast = new MetanetSDKCompat({ readyTimeout: 5, timeoutMs: { pay: 30 } });
    await expect(fast.payBSV([{ address: '1Dest', value: 1 }])).rejects.toThrow('Payment timeout');
  });

  it('payICP nests the legacy token spec and single recipient on the wire', async () => {
    parent.handlers.set('pay', (detail) => {
      respond('pay-response', {
        ref: detail.ref,
        success: true,
        responseCode: 'OK_SUCCESS',
        blockIndex: '42',
      });
    });

    const result = await sdk.payICP('ledger-canister-id', 'recipient-principal', 100000, 'memo-1');

    const frame = parent.postedOf('pay')[0];
    expect(frame.detail.token).toEqual({
      protocol: 'ICP',
      specification: { ledgerId: 'ledger-canister-id' },
    });
    expect(frame.detail.recipients).toEqual([
      { address: 'recipient-principal', value: 100000, note: 'memo-1' },
    ]);
    expect(result.blockIndex).toBe('42');
  });
});

/* ================================================================== *
 * Histories & transactions.
 * ================================================================== */

describe('compat histories / transactions', () => {
  it('getBSVHistory sends legacy defaults (offset 0, limit 50) and resolves the payload', async () => {
    parent.handlers.set('token-history', (detail) => {
      respond('token-history-response', {
        ref: detail.ref,
        success: true,
        responseCode: 'OK_SUCCESS',
        history: [{ txid: 'a' }],
        hasMore: false,
      });
    });

    const result = await sdk.getBSVHistory();

    const frame = parent.postedOf('token-history')[0];
    expect(frame.detail.offset).toBe(0);
    expect(frame.detail.limit).toBe(50);
    expect(result.history).toEqual([{ txid: 'a' }]);
    expect(result.hasMore).toBe(false);
  });

  it('getICPTokenHistory nests the index-canister spec on the wire', async () => {
    parent.handlers.set('token-history', (detail) => {
      respond('token-history-response', {
        ref: detail.ref,
        success: true,
        responseCode: 'OK_SUCCESS',
        transactions: [],
      });
    });

    await sdk.getICPTokenHistory('index-canister-id', { offset: 10, limit: 20 });

    const frame = parent.postedOf('token-history')[0];
    expect(frame.detail.token).toEqual({
      protocol: 'ICP',
      specification: { indexCanisterId: 'index-canister-id' },
    });
    expect(frame.detail.offset).toBe(10);
    expect(frame.detail.limit).toBe(20);
  });

  it('getTokenHistory (deprecated) resolves the history array, not the payload', async () => {
    parent.handlers.set('token-history', (detail) => {
      respond('token-history-response', {
        ref: detail.ref,
        success: true,
        responseCode: 'OK_SUCCESS',
        history: [{ txid: 'legacy-1' }, { txid: 'legacy-2' }],
      });
    });

    const result = await sdk.getTokenHistory('token-1', 25);
    // Legacy resolved payload.history || payload.transactions || [].
    expect(result).toEqual([{ txid: 'legacy-1' }, { txid: 'legacy-2' }]);
    const frame = parent.postedOf('token-history')[0];
    expect(frame.detail.tokenId).toBe('token-1');
    expect(frame.detail.limit).toBe(25);
  });

  it('getFullTransaction maps tx_hex/bump_hex → rawHex/bumpHex (legacy names)', async () => {
    parent.handlers.set('full-transaction', (detail) => {
      respond('full-transaction-response', {
        ref: detail.ref,
        success: true,
        responseCode: 'OK_SUCCESS',
        txid: 'txid-9',
        tx_hex: '0100abcd',
        bump_hex: 'fe12',
      });
    });

    const result = await sdk.getFullTransaction('txid-9');
    expect(result).toEqual({ txid: 'txid-9', rawHex: '0100abcd', bumpHex: 'fe12' });
  });

  it('authorizeSwap spreads swapParams into the command and resolves the payload', async () => {
    parent.handlers.set('authorise-swap', (detail) => {
      respond('authorise-swap-response', {
        ref: detail.ref,
        success: true,
        responseCode: 'OK_SUCCESS',
        authorized: true,
      });
    });

    const result = await sdk.authorizeSwap({ fromToken: 'BSV', toToken: 'ICP', amount: 5 });
    const frame = parent.postedOf('authorise-swap')[0];
    expect(frame.detail.fromToken).toBe('BSV');
    expect(frame.detail.toToken).toBe('ICP');
    expect(frame.detail.amount).toBe(5);
    expect(result.authorized).toBe(true);
  });
});

/* ================================================================== *
 * Geolocation.
 * ================================================================== */

describe('compat geolocation', () => {
  it('getGeolocation resolves the flat legacy location shape', async () => {
    parent.handlers.set('geolocation', (detail) => {
      respond('geolocation-response', {
        ref: detail.ref,
        success: true,
        responseCode: 'OK_SUCCESS',
        latitude: 37.97,
        longitude: 23.72,
        accuracy: 12,
        altitude: 70,
        heading: 90,
        speed: 0,
        timestamp: 1720000000123,
      });
    });

    const fix = await sdk.getGeolocation({ highAccuracy: true });

    // Wire: legacy always sends both flags.
    const frame = parent.postedOf('geolocation')[0];
    expect(frame.detail.watch).toBe(false);
    expect(frame.detail.highAccuracy).toBe(true);

    // Resolved: the exact legacy field set — nothing more, nothing less.
    expect(fix).toEqual({
      latitude: 37.97,
      longitude: 23.72,
      accuracy: 12,
      altitude: 70,
      heading: 90,
      speed: 0,
      timestamp: 1720000000123,
    });
  });

  it('getGeolocation rejects with the legacy message on a failure payload', async () => {
    parent.handlers.set('geolocation', (detail) => {
      respond('geolocation-response', {
        ref: detail.ref,
        success: false,
        responseCode: 'ERR_ABORTED',
        error: 'Location permission denied',
      });
    });

    await expect(sdk.getGeolocation()).rejects.toThrow('Location permission denied');
  });

  it('onGeolocation receives each frame payload; stopGeolocation posts the ref-less stop', async () => {
    const fixes: any[] = [];
    const cleanup = sdk.onGeolocation((p) => fixes.push(p));

    // Two watch frames delivered straight to the mirror (no promise involved).
    self_.deliver({
      command: 'ninja-app-command',
      type: 'geolocation-response',
      payload: { ref: 'watch-1', success: true, latitude: 1, longitude: 2 },
    });
    self_.deliver({
      command: 'ninja-app-command',
      type: 'geolocation-response',
      payload: { ref: 'watch-1', success: true, latitude: 3, longitude: 4 },
    });
    expect(fixes).toHaveLength(2);
    expect(fixes[1].latitude).toBe(3);

    cleanup();
    self_.deliver({
      command: 'ninja-app-command',
      type: 'geolocation-response',
      payload: { ref: 'watch-1', success: true, latitude: 5, longitude: 6 },
    });
    expect(fixes).toHaveLength(2); // unsubscribed

    // Legacy stop: fire-and-forget, no ref field at all.
    sdk.stopGeolocation();
    const stop = parent.postedOf('geolocation-stop')[0];
    expect(stop.detail).toEqual({ type: 'geolocation-stop' });
  });
});

/* ================================================================== *
 * QR scanning — the fire-and-forget + listener pattern.
 * ================================================================== */

describe('compat QR scanning', () => {
  it('scanQRCode returns { ref } immediately and posts the ref it returned', async () => {
    const { ref } = await sdk.scanQRCode({ mode: 'single' });

    expect(typeof ref).toBe('string');
    const frame = parent.postedOf('qr-scan')[0];
    // The RETURNED ref must equal the WIRE ref — apps match listener payloads on it.
    expect(frame.detail.ref).toBe(ref);
    expect(frame.detail.mode).toBe('single');
  });

  it('onQRScanResponse / onQRScanStop receive payloads; stopQRScan posts the ref-less stop', async () => {
    const { ref } = await sdk.scanQRCode();

    const scans: any[] = [];
    const stops: any[] = [];
    const cleanupScan = sdk.onQRScanResponse((p) => scans.push(p));
    sdk.onQRScanStop((p) => stops.push(p));

    self_.deliver({
      command: 'ninja-app-command',
      type: 'qr-scan-response',
      payload: { ref, success: true, data: 'https://scanned.example' },
    });
    expect(scans).toHaveLength(1);
    expect(scans[0].ref).toBe(ref);
    expect(scans[0].data).toBe('https://scanned.example');

    self_.deliver({
      command: 'ninja-app-command',
      type: 'qr-scan-stop-response',
      payload: { ref, success: true },
    });
    expect(stops).toHaveLength(1);

    cleanupScan();
    self_.deliver({
      command: 'ninja-app-command',
      type: 'qr-scan-response',
      payload: { ref, success: true, data: 'second' },
    });
    expect(scans).toHaveLength(1); // unsubscribed

    sdk.stopQRScan();
    const stop = parent.postedOf('qr-scan-stop')[0];
    expect(stop.detail).toEqual({ type: 'qr-scan-stop' });
  });
});

/* ================================================================== *
 * Posts, links, clipboard.
 * ================================================================== */

describe('compat content + utilities', () => {
  it('createPost spreads postData and resolves the raw payload', async () => {
    parent.handlers.set('create-post', (detail) => {
      respond('create-post-response', {
        ref: detail.ref,
        success: true,
        responseCode: 'OK_SUCCESS',
        postId: 'post-77',
      });
    });

    const result = await sdk.createPost({ content: 'gm', metadata: { tag: 'x' } });
    const frame = parent.postedOf('create-post')[0];
    expect(frame.detail.content).toBe('gm');
    expect(frame.detail.metadata).toEqual({ tag: 'x' });
    expect(result.postId).toBe('post-77');
  });

  it('openLink resolves payload.success — true on approve, FALSE on decline (legacy quirk)', async () => {
    parent.handlers.set('open-link', (detail) => {
      respond('open-link-response', {
        ref: detail.ref,
        success: true,
        responseCode: 'OK_SUCCESS',
      });
    });
    await expect(sdk.openLink('https://example.com')).resolves.toBe(true);

    // Declined: legacy RESOLVED false (it never rejected on a failure payload).
    parent.handlers.set('open-link', (detail) => {
      respond('open-link-response', {
        ref: detail.ref,
        success: false,
        responseCode: 'ERR_ABORTED',
        error: 'declined',
      });
    });
    await expect(sdk.openLink('https://example.com')).resolves.toBe(false);
  });

  it('writeClipboard posts the legacy ref-less fire-and-forget frame', () => {
    sdk.writeClipboard('copied text');
    const frame = parent.postedOf('write-clipboard')[0];
    expect(frame).toEqual({
      command: 'ninja-app-command',
      detail: { type: 'write-clipboard', text: 'copied text' },
    });
  });
});

/* ================================================================== *
 * Event registry semantics (on / off / once) + mirror gating.
 * ================================================================== */

describe('compat event registry', () => {
  it('on() callbacks receive the ENTIRE envelope; once() fires exactly once', () => {
    const seen: any[] = [];
    const seenOnce: any[] = [];
    sdk.on('pay-response', (rd) => seen.push(rd));
    sdk.once('pay-response', (rd) => seenOnce.push(rd));

    const envelope = {
      command: 'ninja-app-command',
      type: 'pay-response',
      payload: { ref: 'r1', success: true },
      signature: 'unverified-mirror-frame',
    };
    self_.deliver(envelope);
    self_.deliver(envelope);

    // `on` fires per frame with the FULL envelope (not the payload).
    expect(seen).toHaveLength(2);
    expect(seen[0].command).toBe('ninja-app-command');
    expect(seen[0].payload.ref).toBe('r1');
    // `once` self-removed after the first frame.
    expect(seenOnce).toHaveLength(1);
  });

  it('off() removes by reference; unknown callbacks are a no-op', () => {
    const seen: any[] = [];
    const cb = (rd: any) => seen.push(rd);
    sdk.on('custom-response', cb);
    sdk.off('custom-response', () => {}); // not registered — must not disturb cb
    self_.deliver({ command: 'ninja-app-command', type: 'custom-response', payload: {} });
    expect(seen).toHaveLength(1);

    sdk.off('custom-response', cb);
    self_.deliver({ command: 'ninja-app-command', type: 'custom-response', payload: {} });
    expect(seen).toHaveLength(1);
  });

  it('the mirror drops frames from untrusted origins and foreign sources', () => {
    const seen: any[] = [];
    sdk.on('pay-response', (rd) => seen.push(rd));
    const frame = { command: 'ninja-app-command', type: 'pay-response', payload: { ref: 'r' } };

    self_.deliver(frame, 'https://evil.example', parent); // bad origin
    self_.deliver(frame, ORIGIN, { not: 'the parent' }); // bad source
    expect(seen).toHaveLength(0);

    self_.deliver(frame, ORIGIN, parent); // both gates pass
    expect(seen).toHaveLength(1);
  });
});

/* ================================================================== *
 * Unsupportable drifted inventions — typed ERR_NOT_SUPPORTED.
 * ================================================================== */

describe('compat unsupported drift methods', () => {
  const cases: Array<[string, () => unknown]> = [
    ['requestCamera', () => sdk.requestCamera()],
    ['onCameraFrame', () => sdk.onCameraFrame(() => {})],
    ['captureFrame', () => sdk.captureFrame('ref-1')],
    ['stopCamera', () => sdk.stopCamera('ref-1')],
    ['transcodeVideo', () => sdk.transcodeVideo({} as unknown)],
    ['onTranscodeProgress', () => sdk.onTranscodeProgress(() => {})],
    ['authUser', () => sdk.authUser()],
  ];

  it.each(cases)('%s throws NinjaError(ERR_NOT_SUPPORTED) with a hint', (_name, invoke) => {
    try {
      invoke();
      expect.unreachable('expected a throw');
    } catch (e) {
      expect(isNinjaError(e)).toBe(true);
      if (isNinjaError(e)) {
        expect(e.code).toBe('ERR_NOT_SUPPORTED');
        expect(typeof e.hint).toBe('string');
        expect((e.hint as string).length).toBeGreaterThan(0);
      }
    }
  });
});

/* ================================================================== *
 * SDKProvider drift extras that ARE supportable.
 * ================================================================== */

describe('compat SDKProvider extras', () => {
  it('sendCommand posts the raw detail; onCommand/offCommand see every platform frame', () => {
    sdk.sendCommand({ type: 'custom-thing', foo: 1 });
    const frame = parent.postedOf('custom-thing')[0];
    expect(frame).toEqual({
      command: 'ninja-app-command',
      detail: { type: 'custom-thing', foo: 1 },
    });

    const seen: any[] = [];
    const listener = (rd: any) => seen.push(rd);
    sdk.onCommand(listener);
    self_.deliver({ command: 'ninja-app-command', type: 'anything-response', payload: { ref: 'x' } });
    expect(seen).toHaveLength(1);
    expect(seen[0].type).toBe('anything-response');

    sdk.offCommand(listener);
    self_.deliver({ command: 'ninja-app-command', type: 'anything-response', payload: { ref: 'y' } });
    expect(seen).toHaveLength(1);
  });
});
