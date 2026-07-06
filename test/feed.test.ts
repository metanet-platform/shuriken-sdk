/**
 * shuriken-sdk — feed.createPost wire-shape tests.
 *
 * WHAT: pins the exact bytes `ninja.feed.createPost(...)` hands to `codec.call`.
 *       This is the load-bearing contract with the parent's CreatePost overlay
 *       (metanet_frontend/src/components/CreatePost.js) + mediaHandler.js:
 *         - content is nested under `{ params: {...} }` (mediaHandler reads
 *           `data.detail.params`), and
 *         - the ergonomic `previewAsset: File|Blob` is TRANSLATED into the
 *           overlay's structured `{ type, file, data, mimetype, extension }`
 *           shape — where `data` is a data-URL the overlay renders (line 619) and
 *           `file` is the raw Blob it uploads to IPFS (line 223). A raw Blob has
 *           neither `.data` nor `.preview`, which is why the preview never showed.
 * WHY:  this translation is invisible to the public type (`previewAsset?: File |
 *       Blob`) but is exactly the part that regressed. A test that asserts the
 *       wire shape is the cheapest guard against re-introducing the empty preview.
 *
 * These run under vitest's default node environment, so we hand-roll the two
 * browser globals the conversion touches (`Blob` / `File` / `FileReader`).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';

import { makeFeed } from '../src/commands/feed';
import type { Codec } from '../src/protocol/codec';

/* ------------------------------------------------------------------ *
 * Minimal browser-global fakes (node has no Blob/File/FileReader with
 * readAsDataURL). Just enough surface for feed.ts's conversion path.
 * ------------------------------------------------------------------ */

class FakeBlob {
  readonly type: string;
  readonly #bytes: Uint8Array;
  constructor(parts: Uint8Array[], opts?: { type?: string }) {
    this.type = opts?.type ?? '';
    const len = parts.reduce((n, p) => n + p.length, 0);
    this.#bytes = new Uint8Array(len);
    let off = 0;
    for (const p of parts) {
      this.#bytes.set(p, off);
      off += p.length;
    }
  }
  get bytes(): Uint8Array {
    return this.#bytes;
  }
}

class FakeFile extends FakeBlob {
  readonly name: string;
  constructor(parts: Uint8Array[], name: string, opts?: { type?: string }) {
    super(parts, opts);
    this.name = name;
  }
}

class FakeFileReader {
  result: string | null = null;
  error: unknown = null;
  onload: (() => void) | null = null;
  onerror: (() => void) | null = null;
  readAsDataURL(blob: FakeBlob): void {
    // Encode exactly like the browser: `data:<mime>;base64,<b64>`.
    const b64 = Buffer.from(blob.bytes).toString('base64');
    this.result = `data:${blob.type};base64,${b64}`;
    queueMicrotask(() => this.onload?.());
  }
}

const g = globalThis as unknown as Record<string, unknown>;
let saved: Record<string, unknown>;

beforeAll(() => {
  saved = {
    Blob: g.Blob,
    File: g.File,
    FileReader: g.FileReader,
  };
  g.Blob = FakeBlob;
  g.File = FakeFile;
  g.FileReader = FakeFileReader;
});

afterAll(() => {
  g.Blob = saved.Blob;
  g.File = saved.File;
  g.FileReader = saved.FileReader;
});

/**
 * A codec test-double that captures the last `call(method, params)` and resolves
 * with a fixed post id. Only `call` is exercised by `makeFeed`.
 */
function makeCaptureCodec(): {
  codec: Codec;
  calls: Array<{ method: string; params: unknown }>;
} {
  const calls: Array<{ method: string; params: unknown }> = [];
  const codec = {
    call: (method: string, params: unknown) => {
      calls.push({ method, params });
      return Promise.resolve({ postId: 'post-123' });
    },
  } as unknown as Codec;
  return { codec, calls };
}

describe('feed.createPost wire shape', () => {
  it('nests content under { params } and passes headline through unchanged', async () => {
    const { codec, calls } = makeCaptureCodec();
    const feed = makeFeed(codec);

    const res = await feed.createPost({ headline: 'gm from shuriken-sdk' });

    expect(res).toEqual({ postId: 'post-123' });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe('create-post');
    // The parent reads content off detail.params, so it MUST be nested here.
    expect(calls[0].params).toEqual({ params: { headline: 'gm from shuriken-sdk' } });
  });

  it('passes nftDescription + appEmbed through untouched', async () => {
    const { codec, calls } = makeCaptureCodec();
    const feed = makeFeed(codec);

    const appEmbed = { url: 'https://x.example', type: 'game' as const, shape: 'landscape' as const };
    await feed.createPost({ headline: 'h', nftDescription: 'd', appEmbed });

    expect(calls[0].params).toEqual({
      params: { headline: 'h', nftDescription: 'd', appEmbed },
    });
  });

  it('translates a File previewAsset into the overlay shape { type, file, data, mimetype, extension }', async () => {
    const { codec, calls } = makeCaptureCodec();
    const feed = makeFeed(codec);

    const file = new (g.File as typeof FakeFile)(
      [new Uint8Array([1, 2, 3])],
      'shot.PNG',
      { type: 'image/png' },
    ) as unknown as File;

    await feed.createPost({ headline: 'h', previewAsset: file });

    const sent = (calls[0].params as { params: Record<string, unknown> }).params;
    const preview = sent.previewAsset as Record<string, unknown>;

    // The overlay renders `.data` (a data-URL) and uploads `.file` (the Blob).
    expect(preview.type).toBe('image');
    expect(preview.file).toBe(file); // raw Blob preserved for the IPFS upload path
    expect(preview.data).toBe(
      `data:image/png;base64,${Buffer.from([1, 2, 3]).toString('base64')}`,
    );
    expect(preview.mimetype).toBe('image/png');
    // Extension comes from the filename (lower-cased), not the MIME subtype.
    expect(preview.extension).toBe('png');
    // headline still rides alongside.
    expect(sent.headline).toBe('h');
  });

  it('derives extension from the MIME subtype for a bare Blob (no filename)', async () => {
    const { codec, calls } = makeCaptureCodec();
    const feed = makeFeed(codec);

    const blob = new (g.Blob as typeof FakeBlob)([new Uint8Array([9])], {
      type: 'image/jpeg',
    }) as unknown as Blob;

    await feed.createPost({ headline: 'h', previewAsset: blob });

    const sent = (calls[0].params as { params: Record<string, unknown> }).params;
    const preview = sent.previewAsset as Record<string, unknown>;
    expect(preview.mimetype).toBe('image/jpeg');
    expect(preview.extension).toBe('jpeg');
    expect(preview.file).toBe(blob);
  });

  it('omits previewAsset entirely when none is supplied (no empty key)', async () => {
    const { codec, calls } = makeCaptureCodec();
    const feed = makeFeed(codec);

    await feed.createPost({ headline: 'h' });

    const sent = (calls[0].params as { params: Record<string, unknown> }).params;
    expect('previewAsset' in sent).toBe(false);
  });
});
