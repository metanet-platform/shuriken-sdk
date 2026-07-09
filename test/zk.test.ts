/**
 * shuriken-sdk — ZK proof verification tests.
 *
 * Four layers, weakest to strongest:
 *   1. SPEC UNIT VECTORS — labelToField / computePubCommit / computeLeafHash /
 *      canonicalId codec, pinned against values computed by the PLATFORM's
 *      authoritative implementation (metanet_back/src/services/
 *      identityCircomSpec.js) — a true cross-implementation check — plus an
 *      independent in-test re-derivation via poseidon-lite.
 *   2. VKEY INTEGRITY — the embedded verification keys hash to their pins;
 *      a byte-flip throws ERR_VKEY_INTEGRITY (fail closed).
 *   3. SYNTHETIC GROTH16 — a hand-built satisfied instance with known discrete
 *      logs proves the pairing equation + coordinate conventions are right
 *      even with no fixtures on disk.
 *   4. REAL FIXTURES — proofs minted by the actual vault prover
 *      (test/fixtures/*.json, produced by a parallel job): verify, run the
 *      full tamper matrix, and cross-check verdicts against snarkjs
 *      (dev-only import) on both honest and tampered inputs.
 *
 * Fixture files may not exist yet (they are minted by a parallel agent);
 * fixture-dependent tests then SKIP with a loud console.warn. Layers 1–3 do
 * not depend on fixtures and always run.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { bn254 } from '@noble/curves/bn254';
import { poseidon1 } from 'poseidon-lite/poseidon1';
import { poseidon2 } from 'poseidon-lite/poseidon2';
import { poseidon6 } from 'poseidon-lite/poseidon6';
import { sha256 } from '@noble/hashes/sha2';
import { utf8ToBytes } from '@noble/hashes/utils';

import {
  FIELD_MODULUS,
  DOMAIN_PUB_COMMIT,
  DOMAIN_LEAF,
  IDENTITY_ZK_VERSION,
  CURVE_TAGS,
  IDENTITY_PURPOSE_LABELS_V1,
  IDENTITY_PURPOSE_CURVES,
  assetPurposeLabel,
  labelToField,
  paddedPublicKeyBytes,
  computePubCommit,
  computeLeafHash,
  base58Decode,
  decodeIdentityCanonicalId,
} from '../src/zk/spec';
import { verifyGroth16 } from '../src/zk/groth16';
import { getVerifiedVkey, assertVkeyIntegrity, VKEY_SHA256, type VkeyCurve } from '../src/zk/vkeys';
import { verifyIdentityProof, verifyProofOrThrow } from '../src/commands/identity';
import { isNinjaError, NinjaError } from '../src/errors';
import type { Groth16Proof, ProofEnvelope } from '../src/types';

/* ================================================================== *
 * Test-local helpers (independent re-implementations where possible).
 * ================================================================== */

/** Bitcoin base58 ENCODE — test-local (the SDK only ships decode). */
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Encode(bytes: number[]): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros += 1;
  let num = 0n;
  for (const b of bytes) num = (num << 8n) | BigInt(b);
  let out = '';
  while (num > 0n) {
    out = B58[Number(num % 58n)] + out;
    num /= 58n;
  }
  return '1'.repeat(zeros) + out;
}

/** Encode a seedCommitment into a V1 canonicalId (mirrors the platform encoder). */
function encodeCanonicalId(seedCommitment: bigint): string {
  const payload = [1];
  let rem = seedCommitment;
  const be: number[] = [];
  for (let i = 0; i < 32; i += 1) {
    be.unshift(Number(rem & 0xffn));
    rem >>= 8n;
  }
  payload.push(...be);
  const raw = base58Encode(payload);
  const parts: string[] = [];
  for (let i = 0; i < raw.length; i += 5) parts.push(raw.slice(i, i + 5));
  return parts.join('-');
}

/** Flip the last digit of a decimal-string coordinate ('1' ↔ '2'). */
function flipDigit(s: string): string {
  const last = s[s.length - 1];
  return s.slice(0, -1) + (last === '1' ? '2' : '1');
}

/** Deep-clone a proof envelope so tamper tests never contaminate each other. */
function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

/* ================================================================== *
 * 1. Spec unit vectors.
 * ================================================================== */

describe('zk/spec — cross-implementation unit vectors', () => {
  // Pinned outputs computed by metanet_back/src/services/identityCircomSpec.js
  // (the platform's authoritative implementation) on 2026-07-08. If any of
  // these ever fails, the SDK has drifted from the platform and every honest
  // proof would fail verification — do NOT "fix" the pin, fix the code.
  it('labelToField matches the platform for identity + asset labels', () => {
    expect(labelToField('metanet:purpose:bsv:v1')).toBe(
      8269755511116434925173929140555242017844506079634809834314371105794654695460n,
    );
    expect(labelToField('metanet:purpose:icp:v1')).toBe(
      17085164826615097275199207368119126113425299139711722381379808752904058460561n,
    );
    expect(labelToField('metanet:anchor:identity:v1')).toBe(
      9971709988675100233247314251810575168794317407478545948195609788586404387383n,
    );
    expect(labelToField(assetPurposeLabel('app', 'deadbeef'))).toBe(
      20175724451575700961683307516942079455974543874775317441394316466506610891410n,
    );
  });

  it('labelToField equals the independent sha256→BE-bigint→mod p→poseidon1 derivation', () => {
    const label = 'metanet:purpose:content:v1';
    const digest = sha256(utf8ToBytes(label));
    let n = 0n;
    for (const byte of digest) n = (n << 8n) + BigInt(byte);
    const expected = poseidon1([n % FIELD_MODULUS]) % FIELD_MODULUS;
    expect(labelToField(label)).toBe(expected);
  });

  it('computePubCommit + computeLeafHash match the platform vector', () => {
    const purposeTag = labelToField(IDENTITY_PURPOSE_LABELS_V1['bsv']!);
    const publicKeyBytes = [2, ...Array.from({ length: 32 }, (_, i) => i + 1)];
    const pubCommit = computePubCommit({ purposeTag, curveTag: 2, publicKeyBytes });
    expect(pubCommit).toBe(
      '6398332650630097126480717477142572889676855610894915360780435378211416342242',
    );
    const leafHash = computeLeafHash({
      seedCommitment: '12345678901234567890',
      purposeTag,
      curveTag: 2,
      pubCommit,
    });
    expect(leafHash).toBe(
      '5548569270556092838510823410332336675012444078574154797350189313895849798194',
    );
  });

  it('computePubCommit equals the independent poseidon6-head + poseidon2-fold derivation', () => {
    const purposeTag = 123456789n;
    const bytes = Array.from({ length: 33 }, (_, i) => (i * 7) % 256);
    let acc =
      poseidon6([
        DOMAIN_PUB_COMMIT,
        purposeTag % FIELD_MODULUS,
        2n,
        BigInt(bytes[0]!),
        BigInt(bytes[1]!),
        BigInt(bytes[2]!),
      ]) % FIELD_MODULUS;
    for (let i = 3; i < 33; i += 1) acc = poseidon2([acc, BigInt(bytes[i]!)]) % FIELD_MODULUS;
    expect(computePubCommit({ purposeTag, curveTag: 2, publicKeyBytes: bytes })).toBe(String(acc));

    const leaf =
      poseidon6([DOMAIN_LEAF, 42n, purposeTag % FIELD_MODULUS, 2n, acc, IDENTITY_ZK_VERSION]) %
      FIELD_MODULUS;
    expect(
      computeLeafHash({ seedCommitment: 42n, purposeTag, curveTag: 2, pubCommit: acc }),
    ).toBe(String(leaf));
  });

  it('paddedPublicKeyBytes enforces strict per-curve lengths and right-pads to 33', () => {
    const secp = '02' + 'ab'.repeat(32); // 33 bytes compressed SEC1
    expect(paddedPublicKeyBytes(secp, 'Secp256k1')).toHaveLength(33);
    const ed = 'cd'.repeat(32); // 32 bytes
    const padded = paddedPublicKeyBytes(ed, 'Ed25519');
    expect(padded).toHaveLength(33);
    expect(padded[32]).toBe(0); // right-padded with a zero byte
    expect(paddedPublicKeyBytes('0x' + ed, 'Ed25519')).toEqual(padded); // 0x prefix stripped
    expect(() => paddedPublicKeyBytes(ed, 'Secp256k1')).toThrow(); // 32 bytes ≠ secp
    expect(() => paddedPublicKeyBytes(secp, 'Ed25519')).toThrow(); // 33 bytes ≠ ed
    expect(() => paddedPublicKeyBytes('zz', 'Secp256k1')).toThrow(); // non-hex
    expect(() => paddedPublicKeyBytes('abc', 'Secp256k1')).toThrow(); // odd length
  });
});

describe('zk/spec — canonicalId codec', () => {
  it('decodes the platform-encoded canonicalId (hyphens + base58 + version byte)', () => {
    // Encoded by the platform's encodeIdentityCanonicalId('12345678901234567890').
    expect(
      decodeIdentityCanonicalId('JEKNV-nkbo3-jma5n-REBBJ-CDoXF-VeKkD-56VYc-Sy6aa-Lm4D'),
    ).toBe('12345678901234567890');
  });

  it('round-trips arbitrary seedCommitments through the test-local encoder', () => {
    for (const sc of [0n, 1n, 255n, 2n ** 200n + 12345n, FIELD_MODULUS - 1n]) {
      expect(decodeIdentityCanonicalId(encodeCanonicalId(sc))).toBe(sc.toString());
    }
  });

  it('base58Decode maps leading 1s to zero bytes and rejects bad chars', () => {
    expect([...base58Decode('11')]).toEqual([0, 0]);
    expect(() => base58Decode('0')).toThrow(/invalid base58 char/); // 0 not in alphabet
    expect(() => base58Decode('l')).toThrow(/invalid base58 char/); // l not in alphabet
  });

  it('rejects empty, wrong-length, wrong-version and out-of-field ids', () => {
    expect(() => decodeIdentityCanonicalId('')).toThrow(/empty/);
    expect(() => decodeIdentityCanonicalId('---')).toThrow(/empty/);
    expect(() => decodeIdentityCanonicalId('abc')).toThrow(/33 bytes/);
    // Version byte 0 = V0 legacy id — must NOT ZK-decode.
    const v0 = base58Encode([0, ...new Array<number>(32).fill(7)]);
    expect(() => decodeIdentityCanonicalId(v0)).toThrow(/version/);
    // Payload ≥ FIELD_MODULUS must be rejected (canonical field encoding only).
    const over = base58Encode([1, ...new Array<number>(32).fill(0xff)]);
    expect(() => decodeIdentityCanonicalId(over)).toThrow(/modulus/);
  });
});

/* ================================================================== *
 * 2. Vkey integrity.
 * ================================================================== */

describe('zk/vkeys — SHA-pinned embedded verification keys', () => {
  it('both embedded vkeys pass their pins and parse to nPublic=1 / IC length 2 bn128 keys', () => {
    for (const curve of ['Secp256k1', 'Ed25519'] as const) {
      const vkey = getVerifiedVkey(curve);
      expect(vkey.protocol).toBe('groth16');
      expect(vkey.curve).toBe('bn128');
      expect(vkey.nPublic).toBe(1);
      expect(vkey.IC).toHaveLength(2);
    }
    // The two curves' keys are distinct ceremonies — must not be identical.
    expect(getVerifiedVkey('Secp256k1').IC).not.toEqual(getVerifiedVkey('Ed25519').IC);
  });

  it('a byte-flipped vkey string throws ERR_VKEY_INTEGRITY (fail closed)', () => {
    // Same hash-compare seam the production path uses (assertVkeyIntegrity):
    // flip one byte of a candidate and it must throw the typed error.
    const honest = '{"protocol":"groth16"}';
    const digest = Buffer.from(sha256(utf8ToBytes(honest))).toString('hex');
    expect(() => assertVkeyIntegrity(honest, digest)).not.toThrow();
    const flipped = honest.replace('groth16', 'groth17');
    let caught: unknown;
    try {
      assertVkeyIntegrity(flipped, digest);
    } catch (e) {
      caught = e;
    }
    expect(isNinjaError(caught) && caught.code === 'ERR_VKEY_INTEGRITY').toBe(true);
  });

  it('unknown curve names refuse with ERR_VKEY_INTEGRITY, never undefined behavior', () => {
    expect(() => getVerifiedVkey('P256' as VkeyCurve)).toThrowError(NinjaError);
  });

  it('the pins are exactly the platform-published digests', () => {
    expect(VKEY_SHA256.Secp256k1).toBe(
      '698fe8a75ecebe1f35fc71901ff845255be17aa04bd7308691428a7495ab1916',
    );
    expect(VKEY_SHA256.Ed25519).toBe(
      '1789e6c3d6f3a6900140c8600410a30d14b49db321137397ea75580c358648bd',
    );
  });
});

/* ================================================================== *
 * 3. Synthetic Groth16 instance (fixture-independent pairing test).
 * ================================================================== */

describe('zk/groth16 — synthetic satisfied instance', () => {
  // Build a satisfied Groth16 statement from known discrete logs:
  //   e(A,B) = e(α,β)·e(vk_x,γ)·e(C,δ)  ⇔  a·b ≡ x·y + (ic0+s·ic1)·g + c·d (mod r)
  // This exercises the exact pairing equation + snarkjs coordinate parsing
  // without needing circuit artifacts.
  const r = FIELD_MODULUS; // BN254: scalar order == circom field modulus
  const [x, y, g, d, c, ic0, ic1, s, b] = [3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n];
  const inv = (k: bigint): bigint => {
    let e = r - 2n,
      base = k % r,
      out = 1n;
    while (e > 0n) {
      if (e & 1n) out = (out * base) % r;
      base = (base * base) % r;
      e >>= 1n;
    }
    return out;
  };
  const vkx = (ic0 + s * ic1) % r;
  const a = (((x * y + vkx * g + c * d) % r) * inv(b)) % r;
  const G1 = bn254.G1.Point.BASE;
  const G2 = bn254.G2.Point.BASE;
  const aff1 = (P: typeof G1): string[] => {
    const q = P.toAffine();
    return [q.x.toString(), q.y.toString(), '1'];
  };
  const aff2 = (P: typeof G2): string[][] => {
    const q = P.toAffine();
    return [
      [q.x.c0.toString(), q.x.c1.toString()],
      [q.y.c0.toString(), q.y.c1.toString()],
      ['1', '0'],
    ];
  };
  const vkey = {
    protocol: 'groth16',
    curve: 'bn128',
    nPublic: 1,
    vk_alpha_1: aff1(G1.multiply(x)),
    vk_beta_2: aff2(G2.multiply(y)),
    vk_gamma_2: aff2(G2.multiply(g)),
    vk_delta_2: aff2(G2.multiply(d)),
    IC: [aff1(G1.multiply(ic0)), aff1(G1.multiply(ic1))],
  };
  const proof: Groth16Proof = {
    pi_a: aff1(G1.multiply(a)),
    pi_b: aff2(G2.multiply(b)),
    pi_c: aff1(G1.multiply(c)),
  };

  it('accepts the satisfied instance', () => {
    expect(verifyGroth16(vkey, [s.toString()], proof)).toBe(true);
  });

  it('rejects: wrong signal / tampered pi_a / swapped pi_b Fp2 limbs / oversized signal', () => {
    expect(verifyGroth16(vkey, [(s + 1n).toString()], proof)).toBe(false);
    const badA = clone(proof);
    badA.pi_a = aff1(G1.multiply(a + 1n));
    expect(verifyGroth16(vkey, [s.toString()], badA)).toBe(false);
    const swapped = clone(proof);
    swapped.pi_b = [
      [proof.pi_b[0]![1]!, proof.pi_b[0]![0]!], // c0↔c1 — wrong Fp2 convention
      proof.pi_b[1]!,
      proof.pi_b[2]!,
    ];
    expect(verifyGroth16(vkey, [s.toString()], swapped)).toBe(false);
    // Non-canonical (≥ r) public signal: must be rejected, like snarkjs does.
    expect(verifyGroth16(vkey, [r.toString()], proof)).toBe(false);
  });

  it('rejects malformed encodings without throwing (points off curve, bad shapes, non-affine z)', () => {
    const offCurve = clone(proof);
    offCurve.pi_a = [flipDigit(proof.pi_a[0]!), proof.pi_a[1]!, '1'];
    expect(verifyGroth16(vkey, [s.toString()], offCurve)).toBe(false);
    const badZ = clone(proof);
    badZ.pi_a = [proof.pi_a[0]!, proof.pi_a[1]!, '2'];
    expect(verifyGroth16(vkey, [s.toString()], badZ)).toBe(false);
    expect(verifyGroth16(vkey, [s.toString()], { pi_a: [], pi_b: [], pi_c: [] })).toBe(false);
    expect(verifyGroth16(vkey, ['not-a-number'], proof)).toBe(false);
    expect(verifyGroth16(vkey, [s.toString(), '1'], proof)).toBe(false); // wrong signal count
  });
});

/* ================================================================== *
 * 3b. verifyProofOrThrow — typed failure paths (fixture-independent).
 * ================================================================== */

describe('identity.verifyProofOrThrow — typed ERR_PROOF_INVALID failures', () => {
  const goodId = encodeCanonicalId(42n);
  const envelope = (over: Partial<ProofEnvelope> = {}): ProofEnvelope => ({
    scheme: 'metanet-zk-identity-v1',
    purpose: 'bsv',
    seedCommitment: '42',
    proof: { pi_a: ['1', '2', '1'], pi_b: [['1', '0'], ['2', '0'], ['1', '0']], pi_c: ['1', '2', '1'] },
    ...over,
  });
  const pub = '02' + '11'.repeat(32);

  const codeAndHint = (fn: () => void): { code: string; hint: string } => {
    try {
      fn();
    } catch (e) {
      if (isNinjaError(e)) return { code: e.code, hint: e.hint ?? '' };
      throw e;
    }
    throw new Error('expected a throw');
  };

  it('malformed envelope (wrong scheme / empty points) → ERR_PROOF_INVALID', () => {
    const bad = envelope({ scheme: 'other-scheme' as ProofEnvelope['scheme'] });
    const { code, hint } = codeAndHint(() => verifyProofOrThrow(bad, goodId, pub));
    expect(code).toBe('ERR_PROOF_INVALID');
    expect(hint).toContain('bsv:');
    const empty = envelope({ proof: { pi_a: [], pi_b: [], pi_c: [] } });
    expect(codeAndHint(() => verifyProofOrThrow(empty, goodId, pub)).code).toBe('ERR_PROOF_INVALID');
  });

  it('unknown purpose → ERR_PROOF_INVALID naming the purpose', () => {
    const { code, hint } = codeAndHint(() =>
      verifyProofOrThrow(envelope({ purpose: 'acme.loyalty' }), goodId, pub),
    );
    expect(code).toBe('ERR_PROOF_INVALID');
    expect(hint).toContain('acme.loyalty');
  });

  it('asset purpose without assetId → ERR_PROOF_INVALID', () => {
    const { code, hint } = codeAndHint(() =>
      verifyProofOrThrow(envelope({ purpose: 'app' }), goodId, pub),
    );
    expect(code).toBe('ERR_PROOF_INVALID');
    expect(hint).toContain('assetId');
  });

  it('bad canonicalId / envelope-vs-id seedCommitment mismatch → ERR_PROOF_INVALID', () => {
    expect(codeAndHint(() => verifyProofOrThrow(envelope(), 'not-base58-0OIl', pub)).code).toBe(
      'ERR_PROOF_INVALID',
    );
    // Valid id, but the envelope claims a different seedCommitment.
    const mismatched = envelope({ seedCommitment: '43' });
    const { code, hint } = codeAndHint(() => verifyProofOrThrow(mismatched, goodId, pub));
    expect(code).toBe('ERR_PROOF_INVALID');
    expect(hint).toContain('seedCommitment');
  });

  it('well-formed statement with garbage proof points → ERR_PROOF_INVALID (pairing fail)', () => {
    const { code, hint } = codeAndHint(() => verifyProofOrThrow(envelope(), goodId, pub));
    expect(code).toBe('ERR_PROOF_INVALID');
    expect(hint).toContain('pairing');
    // Boolean form: same failure is a plain false (no throw).
    expect(verifyIdentityProof(envelope(), goodId, pub)).toBe(false);
  });
});

/* ================================================================== *
 * 3c. connect() — out-of-the-box verification of received proofs.
 * ================================================================== */

describe('connect() auto-verifies received proofs (out of the box)', () => {
  const v1PayloadWithBadProof = {
    version: 1,
    canonicalId: encodeCanonicalId(42n),
    identities: {
      app: { pub: '02' + '11'.repeat(32) },
      bsv: {
        address: '1BsvAddr',
        pub: '02' + '22'.repeat(32),
        proof: {
          scheme: 'metanet-zk-identity-v1',
          purpose: 'bsv',
          seedCommitment: '42',
          proof: {
            pi_a: ['1', '2', '1'],
            pi_b: [['1', '0'], ['2', '0'], ['1', '0']],
            pi_c: ['1', '2', '1'],
          },
        },
      },
    },
  };

  const makeStubCodec = (payload: Record<string, unknown>) =>
    ({
      call: () => Promise.resolve({ payload, envelope: { ...payload } }),
    }) as unknown as import('../src/protocol/codec').Codec;

  it('REJECTS the connect with ERR_PROOF_INVALID when a carried proof fails', async () => {
    const { makeConnect } = await import('../src/commands/connect');
    let sessionSet = false;
    const connect = makeConnect(makeStubCodec(v1PayloadWithBadProof), () => {
      sessionSet = true;
    });
    await expect(connect({ request: ['bsv'] })).rejects.toSatisfy(
      (e: unknown) => isNinjaError(e) && e.code === 'ERR_PROOF_INVALID',
    );
    // A rejected connect must NOT have seeded the session key.
    expect(sessionSet).toBe(false);
  });

  it('verifyProofs: false is the documented opt-out (resolves despite the bad proof)', async () => {
    const { makeConnect } = await import('../src/commands/connect');
    const connect = makeConnect(makeStubCodec(v1PayloadWithBadProof), () => {});
    const me = await connect({ request: ['bsv'], verifyProofs: false });
    expect(me.version).toBe(1);
  });

  it('proof-free responses connect untouched (nothing to verify)', async () => {
    const { makeConnect } = await import('../src/commands/connect');
    const payload = {
      version: 1,
      canonicalId: encodeCanonicalId(42n),
      identities: { app: { pub: '02' + '11'.repeat(32) } },
    };
    const connect = makeConnect(makeStubCodec(payload), () => {});
    const me = await connect();
    expect(me.version).toBe(1);
  });
});

/* ================================================================== *
 * 4. Real fixtures (minted by the vault prover) + snarkjs cross-check.
 * ================================================================== */

/**
 * Fixture contract (test/fixtures/<name>.json, minted by the parallel job):
 *   { canonicalId, pub, purpose, seedCommitment, proof: {pi_a,pi_b,pi_c},
 *     assetId?, publicSignals?: [leafHash] }
 * — or the same fields with the envelope nested under `envelope`.
 */
interface Fixture {
  canonicalId: string;
  pub: string;
  envelope: ProofEnvelope;
  publicSignals?: string[];
}

function loadFixture(name: string): Fixture | null {
  let raw: string;
  try {
    raw = readFileSync(fileURLToPath(new URL(`./fixtures/${name}.json`, import.meta.url)), 'utf8');
  } catch {
    // eslint-disable-next-line no-console
    console.warn(
      `\n[zk.test] FIXTURE MISSING: test/fixtures/${name}.json — its verify/tamper/snarkjs tests are SKIPPED. ` +
        'The fixture-minting job may still be running; re-run tests once it lands.\n',
    );
    return null;
  }
  const fx = JSON.parse(raw) as Record<string, unknown>;
  const env = (fx['envelope'] ?? {
    scheme: 'metanet-zk-identity-v1',
    purpose: fx['purpose'],
    seedCommitment: fx['seedCommitment'],
    proof: fx['proof'],
    ...(typeof fx['assetId'] === 'string' ? { assetId: fx['assetId'] } : {}),
  }) as ProofEnvelope;
  return {
    canonicalId: String(fx['canonicalId']),
    pub: String(fx['pub']),
    envelope: env,
    ...(Array.isArray(fx['publicSignals']) ? { publicSignals: fx['publicSignals'] as string[] } : {}),
  };
}

/** Recompute the fixture's leafHash exactly like commands/identity.ts does. */
function statementLeafHash(fx: Fixture): string {
  const purpose = fx.envelope.purpose;
  const identityLabel = IDENTITY_PURPOSE_LABELS_V1[purpose];
  const label =
    identityLabel !== undefined
      ? identityLabel
      : `metanet:purpose:${purpose}:${fx.envelope.assetId}:v1`;
  const curve = identityLabel !== undefined ? IDENTITY_PURPOSE_CURVES[purpose]! : 'Secp256k1';
  const purposeTag = labelToField(label);
  const curveTag = CURVE_TAGS[curve];
  const publicKeyBytes = paddedPublicKeyBytes(fx.pub, curve);
  const pubCommit = computePubCommit({ purposeTag, curveTag, publicKeyBytes });
  return computeLeafHash({
    seedCommitment: decodeIdentityCanonicalId(fx.canonicalId),
    purposeTag,
    curveTag,
    pubCommit,
  });
}

/** snarkjs verdict, mapping "throws on malformed" to plain rejection (false). */
async function snarkjsVerdict(
  curve: VkeyCurve,
  publicSignals: string[],
  proof: Groth16Proof,
): Promise<boolean> {
  const snarkjs = await import('snarkjs');
  try {
    return await snarkjs.groth16.verify(
      JSON.parse(JSON.stringify(getVerifiedVkey(curve))),
      publicSignals,
      { ...proof, protocol: 'groth16', curve: 'bn128' },
    );
  } catch {
    return false;
  }
}

const FIXTURES: Array<{ name: string; curve: VkeyCurve }> = [
  { name: 'identity-bsv', curve: 'Secp256k1' },
  { name: 'identity-icp', curve: 'Ed25519' },
  { name: 'asset-app', curve: 'Secp256k1' },
];

for (const { name, curve } of FIXTURES) {
  const fx = loadFixture(name);
  const maybe = fx ? describe : describe.skip;

  maybe(`fixtures/${name} — real vault-minted proof`, () => {
    it('verifies out of the box (boolean + throwing forms)', () => {
      expect(verifyIdentityProof(fx!.envelope, fx!.canonicalId, fx!.pub)).toBe(true);
      expect(() => verifyProofOrThrow(fx!.envelope, fx!.canonicalId, fx!.pub)).not.toThrow();
    });

    it('the recomputed leafHash matches the prover public signal (when shipped)', () => {
      if (!fx!.publicSignals) return;
      expect(statementLeafHash(fx!)).toBe(fx!.publicSignals[0]);
    });

    it('TAMPER: flipped pi_a digit rejects', () => {
      const env = clone(fx!.envelope);
      env.proof.pi_a[0] = flipDigit(env.proof.pi_a[0]!);
      expect(verifyIdentityProof(env, fx!.canonicalId, fx!.pub)).toBe(false);
    });

    it('TAMPER: swapped pi_b Fp2 limbs reject', () => {
      const env = clone(fx!.envelope);
      env.proof.pi_b = [
        [env.proof.pi_b[0]![1]!, env.proof.pi_b[0]![0]!],
        env.proof.pi_b[1]!,
        env.proof.pi_b[2]!,
      ];
      expect(verifyIdentityProof(env, fx!.canonicalId, fx!.pub)).toBe(false);
    });

    it('TAMPER: wrong pub byte rejects', () => {
      // Alter one payload byte, keeping valid hex and the strict length.
      const pub = fx!.pub;
      const i = pub.length - 2;
      const flippedByte = (parseInt(pub.slice(i), 16) ^ 0x01).toString(16).padStart(2, '0');
      expect(verifyIdentityProof(fx!.envelope, fx!.canonicalId, pub.slice(0, i) + flippedByte)).toBe(
        false,
      );
    });

    it('TAMPER: wrong canonicalId (different seedCommitment) rejects and throws typed', () => {
      const otherSeed = (BigInt(decodeIdentityCanonicalId(fx!.canonicalId)) + 1n) % FIELD_MODULUS;
      const otherId = encodeCanonicalId(otherSeed);
      expect(verifyIdentityProof(fx!.envelope, otherId, fx!.pub)).toBe(false);
      let caught: unknown;
      try {
        verifyProofOrThrow(fx!.envelope, otherId, fx!.pub);
      } catch (e) {
        caught = e;
      }
      expect(isNinjaError(caught) && caught.code === 'ERR_PROOF_INVALID').toBe(true);
    });

    it('TAMPER: wrong purpose rejects', () => {
      const env = clone(fx!.envelope);
      // Re-target to a DIFFERENT purpose on the same curve so the failure is
      // the purposeTag (not a trivial curve/key-length error).
      env.purpose = curve === 'Ed25519' ? (env.purpose === 'icp' ? 'kda' : 'icp') : 'content';
      if (env.purpose === 'content') delete env.assetId;
      expect(verifyIdentityProof(env, fx!.canonicalId, fx!.pub)).toBe(false);
    });

    it('TAMPER: wrong / missing assetId rejects (asset purposes)', () => {
      if (!fx!.envelope.assetId) return; // identity purposes carry no assetId
      const wrong = clone(fx!.envelope);
      wrong.assetId = 'ffffffffffffffffffffffffffffffffffffffff';
      expect(verifyIdentityProof(wrong, fx!.canonicalId, fx!.pub)).toBe(false);
      const missing = clone(fx!.envelope);
      delete missing.assetId;
      expect(verifyIdentityProof(missing, fx!.canonicalId, fx!.pub)).toBe(false);
    });

    it('TAMPER: oversized (non-canonical) leafHash rejects at the pairing layer', () => {
      const vkey = getVerifiedVkey(curve);
      expect(verifyGroth16(vkey, [FIELD_MODULUS.toString()], fx!.envelope.proof)).toBe(false);
      const shifted = (BigInt(statementLeafHash(fx!)) + FIELD_MODULUS).toString();
      expect(verifyGroth16(vkey, [shifted], fx!.envelope.proof)).toBe(false);
    });

    it('CROSS-CHECK: our verifier and snarkjs agree — honest=true, tampered=false', async () => {
      const leafHash = statementLeafHash(fx!);
      const honestOurs = verifyGroth16(getVerifiedVkey(curve), [leafHash], fx!.envelope.proof);
      const honestSnark = await snarkjsVerdict(curve, [leafHash], fx!.envelope.proof);
      expect(honestOurs).toBe(true);
      expect(honestSnark).toBe(true);

      const tampered = clone(fx!.envelope.proof);
      tampered.pi_a[0] = flipDigit(tampered.pi_a[0]!);
      const tamperedOurs = verifyGroth16(getVerifiedVkey(curve), [leafHash], tampered);
      const tamperedSnark = await snarkjsVerdict(curve, [leafHash], tampered);
      expect(tamperedOurs).toBe(false);
      expect(tamperedSnark).toBe(false);
    }, 60_000);
  });
}
