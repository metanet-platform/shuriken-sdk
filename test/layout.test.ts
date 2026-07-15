/**
 * shuriken-sdk — parent chrome geometry (layout) tests.
 *
 * WHAT: pins the two halves of the layout channel:
 *         1. `negotiate()` captures a valid `layout` field off `ninja-ready`
 *            (both body conventions) and OMITS it when absent/malformed —
 *            `undefined` must mean "parent never said", never a fabricated 0;
 *         2. `parseLayoutFrame()` accepts only genuine `ninja-layout` control
 *            frames with a finite, non-negative `navBottom`.
 * WHY:  apps position their chrome below `layout().navBottom`; a parent bug or
 *       foreign frame that smuggled in a bogus value would collapse app UIs to
 *       the viewport top. These tests make the boundary validation load-bearing.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import {
  negotiate,
  nextLayout,
  nextLocale,
  parseLayoutFrame,
  parseLocaleFrame,
} from '../src/transport/handshake';
import { WIRE_COMMAND, type RequestEnvelope } from '../src/types';

/** Minimal TransportLike: records posts, hands us the raw-channel callback. */
class FakeTransport {
  readonly posted: RequestEnvelope[] = [];
  deliver: ((data: unknown) => void) | undefined;
  post(env: RequestEnvelope): void {
    this.posted.push(env);
  }
  onRaw(fn: (data: unknown) => void): () => void {
    this.deliver = fn;
    return () => {};
  }
}

function runNegotiate(t: FakeTransport) {
  return negotiate(t as never, {
    protocols: [1, 0],
    readyTimeout: 10_000,
    capabilitiesFallback: [],
  });
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('ninja-ready layout capture', () => {
  it('captures a top-level layout field', async () => {
    const t = new FakeTransport();
    const p = runNegotiate(t);
    t.deliver!({
      command: WIRE_COMMAND,
      type: 'ninja-ready',
      protocol: 1,
      capabilities: ['pay'],
      layout: { navBottom: 45 },
    });
    const negotiated = await p;
    expect(negotiated.layout).toEqual({ navBottom: 45 });
  });

  it('captures a detail-nested layout field', async () => {
    const t = new FakeTransport();
    const p = runNegotiate(t);
    t.deliver!({
      command: WIRE_COMMAND,
      type: 'ninja-ready',
      detail: { protocol: 1, capabilities: [], layout: { navBottom: 58 } },
    });
    const negotiated = await p;
    expect(negotiated.layout).toEqual({ navBottom: 58 });
  });

  it.each([
    ['absent', undefined],
    ['null', null],
    ['non-object', 45],
    ['missing navBottom', {}],
    ['string navBottom', { navBottom: '45' }],
    ['NaN navBottom', { navBottom: Number.NaN }],
    ['Infinity navBottom', { navBottom: Number.POSITIVE_INFINITY }],
    ['negative navBottom', { navBottom: -1 }],
  ])('omits layout entirely when %s (undefined = "parent never said")', async (_label, layout) => {
    const t = new FakeTransport();
    const p = runNegotiate(t);
    t.deliver!({
      command: WIRE_COMMAND,
      type: 'ninja-ready',
      protocol: 1,
      capabilities: [],
      ...(layout === undefined ? {} : { layout }),
    });
    const negotiated = await p;
    expect(negotiated.layout).toBeUndefined();
  });

  it('has no layout on the assume-legacy path', async () => {
    const t = new FakeTransport();
    const p = runNegotiate(t);
    vi.advanceTimersByTime(10_000);
    const negotiated = await p;
    expect(negotiated.protocol).toBe(0);
    expect(negotiated.layout).toBeUndefined();
  });
});

describe('ninja-hello nav prefs passthrough', () => {
  it('includes nav verbatim in every hello (initial + re-posts) when provided', async () => {
    const t = new FakeTransport();
    const nav = { bg: '#0f172a', width: 'full', roundedBottom: false, sideMargins: 0 };
    const p = negotiate(t as never, {
      protocols: [1, 0],
      readyTimeout: 1_500,
      capabilitiesFallback: [],
      nav,
    });
    vi.advanceTimersByTime(1_500);
    await p;
    expect(t.posted.length).toBeGreaterThanOrEqual(2);
    for (const env of t.posted) {
      expect((env.detail as { nav?: unknown }).nav).toEqual(nav);
    }
  });

  it('omits the nav field entirely when the app sets none', async () => {
    const t = new FakeTransport();
    const p = negotiate(t as never, {
      protocols: [1, 0],
      readyTimeout: 1_500,
      capabilitiesFallback: [],
    });
    vi.advanceTimersByTime(1_500);
    await p;
    expect('nav' in (t.posted[0]!.detail as object)).toBe(false);
  });
});

describe('parseLayoutFrame', () => {
  it('accepts a top-level layout body', () => {
    expect(
      parseLayoutFrame({ command: WIRE_COMMAND, type: 'ninja-layout', layout: { navBottom: 45 } }),
    ).toEqual({ navBottom: 45 });
  });

  it('accepts a detail-nested layout body', () => {
    expect(
      parseLayoutFrame({
        command: WIRE_COMMAND,
        type: 'ninja-layout',
        detail: { layout: { navBottom: 0 } },
      }),
    ).toEqual({ navBottom: 0 });
  });

  it.each([
    ['wrong command', { command: 'other', type: 'ninja-layout', layout: { navBottom: 45 } }],
    ['wrong type', { command: WIRE_COMMAND, type: 'ninja-ready', layout: { navBottom: 45 } }],
    ['no body', { command: WIRE_COMMAND, type: 'ninja-layout' }],
    ['negative', { command: WIRE_COMMAND, type: 'ninja-layout', layout: { navBottom: -3 } }],
    ['non-numeric', { command: WIRE_COMMAND, type: 'ninja-layout', layout: { navBottom: '45' } }],
    ['non-object data', 'ninja-layout'],
    ['null data', null],
  ])('rejects %s', (_label, frame) => {
    expect(parseLayoutFrame(frame)).toBeNull();
  });
});

describe('nextLayout (the live cell transition: validation + change-dedupe)', () => {
  const frame = (navBottom: number) => ({
    command: WIRE_COMMAND,
    type: 'ninja-layout',
    layout: { navBottom },
  });

  it('accepts the first value when no layout was seeded (including navBottom 0)', () => {
    expect(nextLayout(null, frame(0))).toEqual({ navBottom: 0 });
    expect(nextLayout(null, frame(45))).toEqual({ navBottom: 45 });
  });

  it('dedupes a re-announcement of the current value (including navBottom 0)', () => {
    expect(nextLayout({ navBottom: 45 }, frame(45))).toBeNull();
    expect(nextLayout({ navBottom: 0 }, frame(0))).toBeNull();
  });

  it('passes a genuine change through', () => {
    expect(nextLayout({ navBottom: 45 }, frame(58))).toEqual({ navBottom: 58 });
    expect(nextLayout({ navBottom: 45 }, frame(0))).toEqual({ navBottom: 0 });
  });

  it('ignores non-layout and malformed frames regardless of current state', () => {
    expect(nextLayout(null, { command: WIRE_COMMAND, type: 'pay-response' })).toBeNull();
    expect(nextLayout({ navBottom: 45 }, frame(-1 as number))).toBeNull();
    expect(nextLayout({ navBottom: 45 }, 'garbage')).toBeNull();
  });
});

describe('ninja-ready locale capture', () => {
  it.each([
    ['plain code', 'en', 'en'],
    ['region tag', 'pt-BR', 'pt-BR'],
    ['script tag', 'zh-Hant', 'zh-Hant'],
  ])('captures a valid locale (%s)', async (_label, locale, expected) => {
    const t = new FakeTransport();
    const p = runNegotiate(t);
    t.deliver!({ command: WIRE_COMMAND, type: 'ninja-ready', protocol: 1, capabilities: [], locale });
    expect((await p).locale).toBe(expected);
  });

  it.each([
    ['absent', undefined],
    ['non-string', 7],
    ['too short', 'e'],
    ['too long', 'x'.repeat(36)],
    ['markup charset', 'en<script>'],
  ])('omits locale entirely when %s', async (_label, locale) => {
    const t = new FakeTransport();
    const p = runNegotiate(t);
    t.deliver!({
      command: WIRE_COMMAND,
      type: 'ninja-ready',
      protocol: 1,
      capabilities: [],
      ...(locale === undefined ? {} : { locale }),
    });
    expect((await p).locale).toBeUndefined();
  });
});

describe('parseLocaleFrame + nextLocale', () => {
  const frame = (locale: unknown) => ({ command: WIRE_COMMAND, type: 'ninja-locale', locale });

  it('accepts top-level and detail-nested bodies', () => {
    expect(parseLocaleFrame(frame('el'))).toBe('el');
    expect(
      parseLocaleFrame({ command: WIRE_COMMAND, type: 'ninja-locale', detail: { locale: 'ja' } }),
    ).toBe('ja');
  });

  it('rejects wrong command/type and invalid values', () => {
    expect(parseLocaleFrame({ command: 'other', type: 'ninja-locale', locale: 'en' })).toBeNull();
    expect(parseLocaleFrame({ command: WIRE_COMMAND, type: 'ninja-layout', locale: 'en' })).toBeNull();
    expect(parseLocaleFrame(frame('en;drop'))).toBeNull();
    expect(parseLocaleFrame(frame(''))).toBeNull();
  });

  it('nextLocale dedupes the current value and passes changes', () => {
    expect(nextLocale(null, frame('en'))).toBe('en');
    expect(nextLocale('en', frame('en'))).toBeNull();
    expect(nextLocale('en', frame('el'))).toBe('el');
    expect(nextLocale('en', 'garbage')).toBeNull();
  });
});
