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
 *
 *       Since the out-of-the-box verification landed, `generate()` ALSO runs a
 *       real Groth16 check on the returned bundle by default — so these
 *       wire-shape tests pass `verifyProof: false` (the documented client-side
 *       opt-out) to isolate the wire contract from the crypto (which has its
 *       own suite in zk.test.ts), and one test pins that a garbage bundle is
 *       REJECTED by default with ERR_PROOF_INVALID.
 */

import { describe, it, expect } from 'vitest';

import { makeProof } from '../src/commands/proof';
import { isNinjaError } from '../src/errors';
import type { Codec } from '../src/protocol/codec';

/** A codec test-double capturing the last call and resolving a fixed (garbage) proof. */
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
  it('forwards reason and NOTHING else — no purpose field, no verifyProof flag, ever', async () => {
    const { codec, calls } = makeCaptureCodec();
    const proof = makeProof(codec);

    await proof.generate({ reason: 'gate premium', verifyProof: false });

    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe('generate-proof');
    expect(calls[0].params).toEqual({ reason: 'gate premium' });
    expect('purpose' in (calls[0].params as object)).toBe(false);
    expect('verifyProof' in (calls[0].params as object)).toBe(false);
  });

  it('sends an empty params object when called bare (modulo the local opt-out)', async () => {
    const { codec, calls } = makeCaptureCodec();
    const proof = makeProof(codec);

    await proof.generate({ verifyProof: false });

    expect(calls[0].params).toEqual({});
  });

  it('REJECTS a cryptographically invalid bundle by default (ERR_PROOF_INVALID)', async () => {
    const { codec } = makeCaptureCodec(); // resolves a structurally garbage proof
    const proof = makeProof(codec);

    // Default behavior verifies the bundle: the double's fake bundle has no
    // appId and empty proof points, so the local verifier must reject it —
    // proving verification is ON out of the box, not opt-in.
    await expect(proof.generate({ reason: 'x' })).rejects.toSatisfy(
      (e: unknown) => isNinjaError(e) && e.code === 'ERR_PROOF_INVALID',
    );
  });
});
