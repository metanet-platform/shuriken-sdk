/**
 * Tests for the BSV broadcast client + the connect() wire-param mapping.
 *
 * The signing test reproduces the backend verifier byte-for-byte
 * (metanet_back/src/middleware/auth.js): sha256 the canonical JSON, take the
 * ASCII bytes of the hex digest, truncate to the leftmost 32 bytes (what
 * elliptic does for a 512-bit message), then ECDSA-verify the DER signature.
 * If this test passes, the live /data/api endpoint will accept our signature.
 */
import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';

import { signBroadcastRequest } from '../src/broadcast';
import { toConnectionWireParams } from '../src/commands/connect';

// A throwaway fixed key so the test is deterministic. NEVER a real key.
const PRIV = '1'.repeat(64);

describe('signBroadcastRequest', () => {
  it('produces a compressed pubkey and a DER signature the backend scheme verifies', () => {
    const canonical = JSON.stringify({
      data: { action: 'broadcastTransactions', raws: ['00ff'], params: { source: 't', timestamp: 1 } },
    });
    const { pubkey, signature } = signBroadcastRequest(canonical, PRIV);

    // Compressed secp256k1 pub: 33 bytes hex, 02/03 prefix.
    expect(pubkey).toMatch(/^0[23][0-9a-f]{64}$/);

    // Reproduce the backend's message derivation and verify the DER signature.
    const digestHex = bytesToHex(sha256(utf8ToBytes(canonical)));
    const msg = utf8ToBytes(digestHex).slice(0, 32); // elliptic's leftmost-256-bit truncation
    const ok = secp256k1.verify(
      secp256k1.Signature.fromDER(signature),
      msg,
      pubkey,
    );
    expect(ok).toBe(true);
  });

  it('rejects a malformed private key with a clear error', () => {
    expect(() => signBroadcastRequest('{}', 'nope')).toThrow(/64-char/);
  });

  it('accepts a 0x-prefixed private key', () => {
    const { pubkey } = signBroadcastRequest('{}', '0x' + PRIV);
    expect(pubkey).toMatch(/^0[23][0-9a-f]{64}$/);
  });
});

describe('toConnectionWireParams', () => {
  it('maps request/proofs onto the parent identities/appIdentity shape', () => {
    expect(
      toConnectionWireParams({ request: ['bsv', 'icp'], proofs: ['app', 'bsv'], salt: 's1' }),
    ).toEqual({
      identities: { bsv: { proof: true }, icp: {} },
      appIdentity: { proof: true },
      salt: 's1',
    });
  });

  it('emits nothing for an empty params object (bare app-identity connect)', () => {
    expect(toConnectionWireParams({})).toEqual({});
  });

  it('a chain proof without an explicit request still surfaces the identity entry', () => {
    // The parent treats a proof-bearing entry as requested; presence = request.
    expect(toConnectionWireParams({ proofs: ['kda'] })).toEqual({
      identities: { kda: { proof: true } },
    });
  });

  it("routes the 'content' core purpose through identities like any chain purpose", () => {
    // content is the 5th core purpose (pure key purpose — no chain address);
    // on the wire it is a plain identities entry, never app-special-cased.
    expect(toConnectionWireParams({ request: ['content'], proofs: ['content'] })).toEqual({
      identities: { content: { proof: true } },
    });
  });

  it('forwards an unknown/custom future purpose untouched (no SDK release needed)', () => {
    // ProofPurpose is open (string & {}): unknown purposes flow through verbatim.
    expect(toConnectionWireParams({ proofs: ['acme.loyalty'] })).toEqual({
      identities: { 'acme.loyalty': { proof: true } },
    });
  });
});
