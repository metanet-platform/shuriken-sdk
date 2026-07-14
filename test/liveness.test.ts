/**
 * shuriken-sdk — liveness tests (first-message-loss protection).
 *
 * WHAT: pins the three behaviors that let the SDK survive a parent whose
 *       message listener attaches AFTER the app's first post (the normal case:
 *       parents subscribe on iframe `load`, which fires after the app's JS has
 *       already run):
 *         1. `codec.call(..., { resend })` re-posts the SAME envelope (same ref)
 *            on an interval, stops on response, and never exceeds `maxResends`;
 *         2. `negotiate()` re-posts `ninja-hello` throughout the ready window;
 *         3. `makeConnect` arms connection re-posts ONLY on the assume-legacy
 *            path (protocol 0) — a negotiating parent proved it is listening.
 * WHY:  `postMessage` has no delivery receipt. The ~15 hand-copied SDKs all
 *       carried an ad-hoc connection retry loop for exactly this race; dropping
 *       it without absorbing it into the SDK reintroduced "app hangs on connect"
 *       (found in the keepitreel migration, 2026-07-14). These tests make the
 *       protection load-bearing.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { Codec } from '../src/protocol/codec';
import { negotiate } from '../src/transport/handshake';
import {
  makeConnect,
  CONNECTION_RESEND_INTERVAL_MS,
  CONNECTION_MAX_RESENDS,
} from '../src/commands/connect';
import { WIRE_COMMAND, type RequestEnvelope, type ResponseEnvelope } from '../src/types';

/** A TransportLike that records outbound envelopes (codec only needs `post`). */
class RecordingTransport {
  readonly posted: RequestEnvelope[] = [];
  post(env: RequestEnvelope): void {
    this.posted.push(env);
  }
}

/** Fresh codec over a recording transport with a null session (pre-connect). */
function makeCodec(t: RecordingTransport): Codec {
  return new Codec(t, {
    timeouts: { default: 30_000 },
    defaultTimeout: 30_000,
    getSession: () => ({ pub: null, version: undefined, genericUseSeed: null }),
    onEvent: () => {},
  });
}

/** Build the success response envelope for a posted request (echoes its ref). */
function responseFor(env: RequestEnvelope, extra: Record<string, unknown> = {}): ResponseEnvelope {
  return {
    command: WIRE_COMMAND,
    type: `${env.detail.type}-response` as `${string}-response`,
    payload: {
      ref: env.detail.ref,
      success: true,
      responseCode: 'OK_SUCCESS',
      ...extra,
    },
    signature: '',
  };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('codec.call resend (CallOptions.resend)', () => {
  it('re-posts the SAME envelope (same ref) on the interval until a response arrives', async () => {
    const t = new RecordingTransport();
    const codec = makeCodec(t);

    const p = codec.call('connection', {}, { resend: { intervalMs: 1_000, maxResends: 6 } });

    // Initial post happened synchronously.
    expect(t.posted).toHaveLength(1);

    // Two intervals pass with no response -> two re-posts, byte-identical ref.
    vi.advanceTimersByTime(2_000);
    expect(t.posted).toHaveLength(3);
    const refs = new Set(t.posted.map((e) => e.detail.ref));
    expect(refs.size).toBe(1); // one shared correlation ref across all posts

    // The response settles the call and stops the resend interval.
    codec.handleResponse(responseFor(t.posted[0]!));
    await expect(p).resolves.toMatchObject({ responseCode: 'OK_SUCCESS' });

    vi.advanceTimersByTime(10_000);
    expect(t.posted).toHaveLength(3); // no further posts after settlement
  });

  it('caps re-posts at maxResends and still times out cleanly', async () => {
    const t = new RecordingTransport();
    const codec = makeCodec(t);

    const p = codec.call(
      'connection',
      {},
      { timeoutMs: 20_000, resend: { intervalMs: 1_000, maxResends: 3 } },
    );
    const rejection = expect(p).rejects.toMatchObject({ code: 'ERR_TIMEOUT' });

    // Run past many would-be intervals: 1 initial + 3 resends, then the cap holds.
    vi.advanceTimersByTime(15_000);
    expect(t.posted).toHaveLength(4);

    vi.advanceTimersByTime(10_000); // cross the 20s timeout
    await rejection;
    expect(t.posted).toHaveLength(4);
  });

  it('does not arm any resend when the option is absent (default unchanged)', async () => {
    const t = new RecordingTransport();
    const codec = makeCodec(t);

    const p = codec.call('open-link', { url: 'https://example.com' }, { timeoutMs: 5_000 });
    const rejection = expect(p).rejects.toMatchObject({ code: 'ERR_TIMEOUT' });
    vi.advanceTimersByTime(5_100);
    await rejection;
    expect(t.posted).toHaveLength(1);
  });
});

describe('handshake ninja-hello re-posts', () => {
  it('re-posts ninja-hello during the ready window, then assumes legacy', async () => {
    const t = new RecordingTransport() as RecordingTransport & {
      onRaw: (fn: (data: unknown) => void) => () => void;
    };
    t.onRaw = () => () => {};

    const p = negotiate(t as never, {
      protocols: [1, 0],
      readyTimeout: 1_500,
      capabilitiesFallback: ['connection', 'pay'],
    });

    expect(t.posted).toHaveLength(1); // immediate hello

    vi.advanceTimersByTime(1_500); // window elapses: ~3 re-posts at 400ms, then settle
    const negotiated = await p;

    expect(negotiated.protocol).toBe(0);
    expect(t.posted.length).toBeGreaterThanOrEqual(3);
    for (const env of t.posted) {
      expect((env as unknown as { type: string }).type).toBe('ninja-hello');
    }

    // Settled: the hello interval is torn down.
    const after = t.posted.length;
    vi.advanceTimersByTime(5_000);
    expect(t.posted).toHaveLength(after);
  });

  it('stops re-posting the instant ninja-ready arrives', async () => {
    let deliver: ((data: unknown) => void) | undefined;
    const t = new RecordingTransport() as RecordingTransport & {
      onRaw: (fn: (data: unknown) => void) => () => void;
    };
    t.onRaw = (fn) => {
      deliver = fn;
      return () => {};
    };

    const p = negotiate(t as never, {
      protocols: [1, 0],
      readyTimeout: 10_000,
      capabilitiesFallback: [],
    });

    vi.advanceTimersByTime(800); // a couple of re-posts happen first
    deliver!({ command: WIRE_COMMAND, type: 'ninja-ready', protocol: 1, capabilities: ['pay'] });
    const negotiated = await p;
    expect(negotiated.protocol).toBe(1);

    const after = t.posted.length;
    vi.advanceTimersByTime(5_000);
    expect(t.posted).toHaveLength(after); // interval cleared on settle
  });
});

describe('makeConnect resend gating by negotiated protocol', () => {
  async function runConnect(protocol: number): Promise<RecordingTransport> {
    const t = new RecordingTransport();
    const codec = makeCodec(t);
    const connect = makeConnect(codec, () => {}, () => protocol);

    const p = connect(); // bare connect (no identities) -> anonymous reply below
    expect(t.posted).toHaveLength(1);

    // Let two would-be resend intervals elapse before the parent answers.
    vi.advanceTimersByTime(CONNECTION_RESEND_INTERVAL_MS * 2);
    codec.handleResponse(responseFor(t.posted[0]!, { anonymous: true }));
    await p;
    return t;
  }

  it('protocol 0 (assume-legacy): arms connection re-posts', async () => {
    const t = await runConnect(0);
    expect(t.posted.length).toBe(3); // initial + 2 resends before the reply
    expect(new Set(t.posted.map((e) => e.detail.ref)).size).toBe(1);
  });

  it('protocol 1 (negotiated parent): posts exactly once', async () => {
    const t = await runConnect(1);
    expect(t.posted).toHaveLength(1);
  });

  it('legacy resend budget matches the documented window (~9s)', () => {
    expect(CONNECTION_RESEND_INTERVAL_MS * CONNECTION_MAX_RESENDS).toBe(9_000);
  });
});
