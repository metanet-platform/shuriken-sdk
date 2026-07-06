/**
 * shuriken-sdk — smoke tests.
 *
 * WHAT: fast, dependency-free unit tests over the SDK's load-bearing pure
 *       functions — the wire-envelope builder + response guard, the correlation
 *       ref generator, the V0/V1/anonymous connection normalizer, and the error
 *       taxonomy's `fromPayload` constructor. Where a function reaches for the
 *       platform (`window` / `postMessage`), we inject a hand-rolled fake so the
 *       tests run under vitest's default node environment with no jsdom.
 * WHY:  these four surfaces are exactly where the ~15 hand-copied SDKs drifted —
 *       envelope shape, ref uniqueness, the V0/V1 identity mixup, and collapsing
 *       every failure into one opaque string. A smoke test that pins their
 *       observable contract is the cheapest guard against re-introducing those
 *       bugs, and it doubles as executable documentation of the wire shape.
 *
 * These are intentionally "smoke" tests: broad, shallow coverage of the happy +
 * key edge paths, not exhaustive property tests. They must stay fast and hermetic.
 */

import { describe, it, expect } from 'vitest';

import { buildRequest, isResponseEnvelope, responseMethod } from '../src/protocol/envelope';
import { newRef } from '../src/protocol/correlation';
import {
  normalizeConnection,
  sessionPubOf,
  sessionVersionOf,
} from '../src/protocol/normalize';
import { toBsvWireRecipients } from '../src/commands/pay';
import { NinjaError, isNinjaError } from '../src/errors';
import { WIRE_COMMAND, type ResponsePayload } from '../src/types';

/* ================================================================== *
 * 1. Envelope build + guard.
 * ================================================================== */

describe('protocol/envelope', () => {
  it('buildRequest wraps method+ref+params in the frozen wire shape', () => {
    // The exact bytes the parent expects: command + echoed type marker, and a
    // `detail` carrying the method (`detail.type`), correlation id (`detail.ref`),
    // and the spread params.
    const env = buildRequest('pay', 'ref-123', {
      recipients: [{ address: '1A1z', sats: 5000 }],
    });

    expect(env.command).toBe(WIRE_COMMAND);
    expect(env.type).toBe(WIRE_COMMAND);
    expect(env.detail.type).toBe('pay');
    expect(env.detail.ref).toBe('ref-123');
    // Params are spread into detail alongside the protocol fields.
    expect(env.detail).toMatchObject({
      type: 'pay',
      ref: 'ref-123',
      recipients: [{ address: '1A1z', sats: 5000 }],
    });
  });

  it('buildRequest protocol fields win over params named type/ref', () => {
    // A hostile/careless params object must not be able to shadow the real method
    // or correlation id — the envelope's own `type`/`ref` are authoritative.
    const env = buildRequest('open-link', 'real-ref', {
      // These collide with protocol fields on purpose.
      type: 'evil',
      ref: 'evil-ref',
      url: 'https://example.com',
    } as Record<string, unknown>);

    expect(env.detail.type).toBe('open-link');
    expect(env.detail.ref).toBe('real-ref');
    expect((env.detail as Record<string, unknown>)['url']).toBe('https://example.com');
  });

  it('buildRequest does not mutate the caller params', () => {
    // Spread-by-value: the caller's object is untouched (no injected type/ref).
    const params = { url: 'https://example.com' };
    buildRequest('open-link', 'r1', params);
    expect(params).toEqual({ url: 'https://example.com' });
    expect('type' in params).toBe(false);
    expect('ref' in params).toBe(false);
  });

  it('isResponseEnvelope accepts a well-formed response frame', () => {
    const frame = {
      command: WIRE_COMMAND,
      type: 'pay-response',
      payload: { ref: 'r1', success: true, responseCode: 'OK_SUCCESS' },
      signature: '3045deadbeef',
    };
    expect(isResponseEnvelope(frame)).toBe(true);
  });

  it('isResponseEnvelope rejects non-envelopes, wrong command, bad type, missing ref', () => {
    // Non-objects.
    expect(isResponseEnvelope(null)).toBe(false);
    expect(isResponseEnvelope(undefined)).toBe(false);
    expect(isResponseEnvelope('pay-response')).toBe(false);
    expect(isResponseEnvelope(42)).toBe(false);
    // Wrong command marker (some other page message).
    expect(
      isResponseEnvelope({ command: 'other', type: 'pay-response', payload: { ref: 'r' } }),
    ).toBe(false);
    // Type not ending in -response (e.g. the ninja-ready handshake frame).
    expect(
      isResponseEnvelope({ command: WIRE_COMMAND, type: 'ninja-ready', payload: { ref: 'r' } }),
    ).toBe(false);
    // Payload present but no string ref (not correlatable).
    expect(
      isResponseEnvelope({ command: WIRE_COMMAND, type: 'pay-response', payload: { success: true } }),
    ).toBe(false);
    // Payload is an array (typeof object, but never a valid payload).
    expect(
      isResponseEnvelope({ command: WIRE_COMMAND, type: 'pay-response', payload: [] }),
    ).toBe(false);
  });

  it('responseMethod strips exactly the trailing -response', () => {
    expect(responseMethod('pay-response')).toBe('pay');
    expect(responseMethod('connection-response')).toBe('connection');
    expect(responseMethod('geolocation-response')).toBe('geolocation');
    // Defensive: a non -response input is returned unchanged.
    expect(responseMethod('pay')).toBe('pay');
  });
});

/* ================================================================== *
 * 2. Correlation ref.
 * ================================================================== */

describe('protocol/correlation', () => {
  it('newRef returns a sanitizer-safe UUID (<=64 chars, allow-list only)', () => {
    const ref = newRef();
    expect(typeof ref).toBe('string');
    // A UUIDv4 is 36 chars — comfortably under the wire's <=256 cap and the V1
    // sanitizer's <=64. The 36-length assertion pins the documented shape.
    expect(ref.length).toBe(36);
    expect(ref.length).toBeLessThanOrEqual(64);
    // Only characters in the V1 sanitizer allow-list /^[A-Za-z0-9._-]{1,64}$/.
    expect(ref).toMatch(/^[A-Za-z0-9._-]{1,64}$/);
    // And specifically the UUIDv4 shape.
    expect(ref).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  it('newRef is unique across many calls (no shared-id collision bug)', () => {
    const N = 1000;
    const seen = new Set<string>();
    for (let i = 0; i < N; i++) seen.add(newRef());
    expect(seen.size).toBe(N);
  });
});

/* ================================================================== *
 * 3. Connection normalization — the V0/V1/anon discriminated union.
 * ================================================================== */

describe('protocol/normalize', () => {
  it('normalizes a V0 wallet payload', () => {
    const payload = {
      version: 0,
      canonicalId: 'canon-v0',
      wallet: {
        address: '1A1zP1eP',
        publicKeyHex: '02aabbccdd',
        rootPrincipal: 'root-xyz',
        bsvPubKey: '02bbccddee',
      },
    };
    const me = normalizeConnection(payload);

    expect(me.anonymous).toBe(false);
    expect(me.version).toBe(0);
    expect(me.canonicalId).toBe('canon-v0');
    // The escape hatch preserves the untouched original payload.
    expect(me.connected).toBe(true);
    expect(me.raw).toEqual(payload);
    // Version-narrowed field access (the mixup the union prevents).
    if (me.version === 0) {
      expect(me.wallet.publicKeyHex).toBe('02aabbccdd');
      // sessionPubOf picks the V0 signing key.
      expect(sessionPubOf(me)).toBe('02aabbccdd');
      expect(sessionVersionOf(me)).toBe(0);
    } else {
      throw new Error('expected V0 identity');
    }
  });

  it('normalizes a V1 identities payload', () => {
    const payload = {
      version: 1,
      canonicalId: 'canon-v1',
      identities: {
        app: { pub: '03appkey' },
        bsv: { address: '1BsvAddr', pub: '03bsvkey' },
      },
    };
    const me = normalizeConnection(payload);

    expect(me.anonymous).toBe(false);
    expect(me.version).toBe(1);
    expect(me.canonicalId).toBe('canon-v1');
    expect(me.connected).toBe(true);
    expect(me.raw).toEqual(payload);
    if (me.version === 1) {
      // The app key is what every V1 response is verified against.
      expect(me.app.pub).toBe('03appkey');
      expect(me.bsv?.pub).toBe('03bsvkey');
      expect(sessionPubOf(me)).toBe('03appkey');
      expect(sessionVersionOf(me)).toBe(1);
    } else {
      throw new Error('expected V1 identity');
    }
  });

  it('normalizes an anonymous payload (no wallet, no identities)', () => {
    const payload = { anonymous: true };
    const me = normalizeConnection(payload);

    expect(me.anonymous).toBe(true);
    expect(me.canonicalId).toBeNull();
    expect(me.version).toBeUndefined();
    // No signing key for an anonymous session.
    expect(sessionPubOf(me)).toBeNull();
    expect(sessionVersionOf(me)).toBeUndefined();
  });

  it('treats an empty/unknown payload as anonymous (never guesses a version)', () => {
    // Per AGENTS.md rule: a payload with neither wallet nor identities is anon —
    // the normalizer must not invent a version.
    const me = normalizeConnection({});
    expect(me.anonymous).toBe(true);
    expect(me.canonicalId).toBeNull();
    expect(me.version).toBeUndefined();
  });
});

/* ================================================================== *
 * 4. Error taxonomy — fromPayload.
 * ================================================================== */

describe('errors/NinjaError.fromPayload', () => {
  it('maps a failed payload responseCode to the error code + carries ref/method/payload', () => {
    const payload: ResponsePayload = {
      ref: 'r-err',
      success: false,
      responseCode: 'ERR_MULTIPLE_RECIPIENTS',
    };
    const err = NinjaError.fromPayload(payload, 'pay');

    expect(isNinjaError(err)).toBe(true);
    expect(err).toBeInstanceOf(NinjaError);
    expect(err.code).toBe('ERR_MULTIPLE_RECIPIENTS');
    expect(err.method).toBe('pay');
    expect(err.ref).toBe('r-err');
    expect(err.payload).toBe(payload);
    // Not in the retriable set.
    expect(err.retriable).toBe(false);
    // Docs deep-link is the lowercased code appended to the base anchor.
    expect(err.docsUrl.endsWith('err_multiple_recipients')).toBe(true);
  });

  it('flags retriable codes (e.g. ERR_TIMEOUT) as retriable', () => {
    const payload: ResponsePayload = {
      ref: 'r-timeout',
      success: false,
      responseCode: 'ERR_TIMEOUT',
    };
    const err = NinjaError.fromPayload(payload, 'full-transaction');
    expect(err.code).toBe('ERR_TIMEOUT');
    expect(err.retriable).toBe(true);
  });

  it('falls back to ERR_UNKNOWN when responseCode is absent', () => {
    // A malformed failure payload with no responseCode must still yield a typed,
    // catchable error rather than `undefined` as a code.
    const payload = { ref: 'r-x', success: false } as ResponsePayload;
    const err = NinjaError.fromPayload(payload, 'pay');
    expect(err.code).toBe('ERR_UNKNOWN');
    expect(err.retriable).toBe(true); // ERR_UNKNOWN is in the retriable set.
  });
});

/* ================================================================== *
 * 5. Fake Window / postMessage harness (documented for reuse).
 *
 * WHY here: several SDK modules (Transport, Codec) drive `postMessage`. The
 * smoke suite doesn't exercise the full transport, but it MUST prove the fake
 * harness the heavier tests rely on behaves like a `Window` closely enough:
 * `postMessage` enqueues, and `addEventListener('message', ...)` receives a
 * `{ data, origin, source }` event. This keeps the harness honest in one place.
 * ================================================================== */

/**
 * A minimal `Window`-like stub: records posted messages and can dispatch a
 * synthetic inbound `message` event to registered listeners. Enough for the
 * transport/codec tests; NOT a full DOM.
 */
class FakeWindow {
  /** Everything `postMessage` was called with, in order (for outbound assertions). */
  readonly posted: Array<{ data: unknown; targetOrigin: string }> = [];
  /** Registered `message` listeners. */
  private readonly listeners = new Set<(ev: MessageEvent) => void>();

  postMessage(data: unknown, targetOrigin: string): void {
    this.posted.push({ data, targetOrigin });
  }

  addEventListener(type: string, fn: (ev: MessageEvent) => void): void {
    if (type === 'message') this.listeners.add(fn);
  }

  removeEventListener(type: string, fn: (ev: MessageEvent) => void): void {
    if (type === 'message') this.listeners.delete(fn);
  }

  /** Deliver a synthetic inbound message to every registered listener. */
  deliver(data: unknown, origin: string, source: unknown): void {
    const ev = { data, origin, source } as unknown as MessageEvent;
    for (const fn of [...this.listeners]) fn(ev);
  }
}

describe('test harness: FakeWindow', () => {
  it('records postMessage calls', () => {
    const w = new FakeWindow();
    const env = buildRequest('pay', 'r1', { recipients: [] });
    w.postMessage(env, '*');
    expect(w.posted).toHaveLength(1);
    expect(w.posted[0]?.targetOrigin).toBe('*');
    expect(isResponseEnvelope(w.posted[0]?.data)).toBe(false); // it's a REQUEST, not a response
  });

  it('dispatches inbound messages to listeners as {data,origin,source}', () => {
    const w = new FakeWindow();
    const received: Array<{ data: unknown; origin: string }> = [];
    const handler = (ev: MessageEvent): void => {
      received.push({ data: ev.data, origin: ev.origin });
    };
    w.addEventListener('message', handler);

    const frame = {
      command: WIRE_COMMAND,
      type: 'pay-response',
      payload: { ref: 'r1', success: true, responseCode: 'OK_SUCCESS' },
    };
    w.deliver(frame, 'https://metanet.page', w);

    expect(received).toHaveLength(1);
    expect(received[0]?.origin).toBe('https://metanet.page');
    expect(isResponseEnvelope(received[0]?.data)).toBe(true);

    // removeEventListener actually unsubscribes.
    w.removeEventListener('message', handler);
    w.deliver(frame, 'https://metanet.page', w);
    expect(received).toHaveLength(1);
  });
});

/* ================================================================== *
 * 6. pay.bsv wire mapping (ergonomic sats/usd/fee -> parent value/fiatValue/reason).
 * ================================================================== */

describe('commands/pay · toBsvWireRecipients', () => {
  it('maps sats -> value (satoshis) and passes address/note through', () => {
    // The exact bug: the demo sends { address, sats, note }; the parent's
    // handler reads r.value (not r.sats) and would otherwise drop the recipient.
    expect(
      toBsvWireRecipients([{ address: '1A1z', sats: 5000, note: 'shuriken demo' }]),
    ).toEqual([{ address: '1A1z', value: 5000, note: 'shuriken demo' }]);
  });

  it('maps usd -> fiatValue for a fiat-denominated recipient', () => {
    expect(toBsvWireRecipients([{ address: '1B', usd: 2.5 }])).toEqual([
      { address: '1B', fiatValue: 2.5 },
    ]);
  });

  it('maps fee -> reason for a fee-only recipient (no address)', () => {
    expect(toBsvWireRecipients([{ fee: 'APP_GENERIC' }])).toEqual([{ reason: 'APP_GENERIC' }]);
  });

  it('emits only the fields that are present (no undefined value/fiatValue leaks)', () => {
    const [wire] = toBsvWireRecipients([{ address: '1C', sats: 1 }]);
    expect(wire).toEqual({ address: '1C', value: 1 });
    expect('fiatValue' in (wire as object)).toBe(false);
    expect('reason' in (wire as object)).toBe(false);
    expect('note' in (wire as object)).toBe(false);
  });

  it('maps a mixed batch (value recipient + fiat recipient + fee-only) in order', () => {
    expect(
      toBsvWireRecipients([
        { address: '1D', sats: 100, note: 'a' },
        { address: '1E', usd: 1 },
        { fee: 'AI_IMG' },
      ]),
    ).toEqual([
      { address: '1D', value: 100, note: 'a' },
      { address: '1E', fiatValue: 1 },
      { reason: 'AI_IMG' },
    ]);
  });
});
