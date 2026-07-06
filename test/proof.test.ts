/**
 * shuriken-sdk — proof.generate wire-shape tests.
 *
 * WHAT: pins the exact params `ninja.proof.generate(...)` hands to
 *       `codec.call('generate-proof', …)`.
 * WHY:  generate-proof is the APP-identity-proof-only shortcut. The parent only
 *       ever mints the `app` proof here, so the SDK must NOT send a `purpose`
 *       field (the old param existed but was ignored parent-side — a trap).
 *       Proofs for other purposes go through the re-callable
 *       `ninja.connect({ request, proofs })` instead.
 */

import { describe, it, expect } from 'vitest';

import { makeProof } from '../src/commands/proof';
import type { Codec } from '../src/protocol/codec';

/** A codec test-double capturing the last call and resolving a fixed proof. */
function makeCaptureCodec(): {
  codec: Codec;
  calls: Array<{ method: string; params: unknown }>;
} {
  const calls: Array<{ method: string; params: unknown }> = [];
  const codec = {
    call: (method: string, params: unknown) => {
      calls.push({ method, params });
      return Promise.resolve({
        canonicalId: 'canon-1',
        pub: '03appkey',
        proof: { pi_a: [], pi_b: [], pi_c: [] },
        seedCommitment: 'sc-1',
      });
    },
  } as unknown as Codec;
  return { codec, calls };
}

describe('proof.generate wire shape (app-proof-only shortcut)', () => {
  it('forwards reason and NOTHING else — no purpose field, ever', async () => {
    const { codec, calls } = makeCaptureCodec();
    const proof = makeProof(codec);

    await proof.generate({ reason: 'gate premium' });

    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe('generate-proof');
    expect(calls[0].params).toEqual({ reason: 'gate premium' });
    expect('purpose' in (calls[0].params as object)).toBe(false);
  });

  it('sends an empty params object when called bare', async () => {
    const { codec, calls } = makeCaptureCodec();
    const proof = makeProof(codec);

    await proof.generate();

    expect(calls[0].params).toEqual({});
  });
});
