/**
 * shuriken-sdk — the `metanet-zk-identity-v1` circuit spec: shared constants
 * and pure statement-building helpers.
 *
 * WHAT: everything a verifier needs to REBUILD the single public signal
 *       (`leafHash`) of an identity/asset Groth16 proof from public inputs:
 *       field constants, domain separators, purpose labels, `labelToField`,
 *       public-key padding, `computePubCommit`, `computeLeafHash`, and the
 *       canonicalId → seedCommitment codec.
 * WHY:  the verifier NEVER trusts a prover-supplied leafHash — it recomputes
 *       the statement from the canonicalId + purpose + public key and only
 *       then runs the pairing check. Every constant and every hash layout in
 *       this file is byte-compatible with the platform's authoritative
 *       `metanet_back/src/services/identityCircomSpec.js` (which itself
 *       mirrors `metanet_frontend/src/services/identityCircomSpec.js` and the
 *       vault prover). ANY drift here produces a leafHash mismatch and every
 *       honest proof silently fails — so nothing in this file may change
 *       without changing all three platform copies in lockstep.
 */

import { sha256 } from '@noble/hashes/sha2';
import { utf8ToBytes } from '@noble/hashes/utils';
import { poseidon1, poseidon2, poseidon6 } from './poseidon';
import { CORE_IDENTITY_PURPOSES } from '../types';

/* ------------------------------------------------------------------ *
 * Constants — pinned to identityCircomSpec.js, never derived.
 * ------------------------------------------------------------------ */

/** BN254 scalar-field modulus (circom's native field). Every hashed value is reduced mod this. */
export const FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Circuit version constant baked into every leafHash (6th poseidon input). */
export const IDENTITY_ZK_VERSION = 1n;

/** The proof envelope scheme tag this verifier understands. */
export const IDENTITY_ZK_SCHEME = 'metanet-zk-identity-v1' as const;

/** canonicalId payload version byte for V1 ZK identities (V0 legacy ids use 0 and are NOT ZK-decodable). */
export const IDENTITY_CANONICAL_ID_VERSION_BYTE = 1;

/** Circuit-level curve tags: which key-derivation gadget produced the purpose public key. */
export const CURVE_TAGS = Object.freeze({ Ed25519: 1, Secp256k1: 2 } as const);

/** The curve names {@link CURVE_TAGS} is keyed by. */
export type CurveName = keyof typeof CURVE_TAGS;

/**
 * Domain separators for the two Poseidon hash roles (public-key commitment vs
 * leaf). Distinct domains make a pubCommit collision with a leafHash
 * structurally impossible. Values pinned to identityCircomSpec.js.
 */
export const DOMAIN_PUB_COMMIT = 230923650770604732136778643887420133092n;
export const DOMAIN_LEAF = 195805090508852503871997862166807589213n;

/** Public keys enter the circuit as exactly 33 byte-signals (compressed SEC1 width). */
export const PUBLIC_KEY_SIGNAL_BYTES = 33;

/* ------------------------------------------------------------------ *
 * Purpose labels — the human-readable strings whose Poseidon field images
 * are the circuit's `purposeTag` input.
 * ------------------------------------------------------------------ */

/**
 * Identity-level purposes carrying a Groth16 proof, and their label strings.
 *
 * Derived from {@link CORE_IDENTITY_PURPOSES} minus `'app'` (an ASSET purpose
 * — its label bakes an assetId, see {@link assetPurposeLabel}), plus the two
 * platform-internal purposes (`mutation`, `session`) that never surface via
 * the SDK wire but exist so a server-side consumer can verify registration
 * proofs with the same module. Labels are byte-identical to
 * `IDENTITY_PURPOSE_LABELS_V1` in identityCircomSpec.js.
 */
export const IDENTITY_PURPOSE_LABELS_V1: Readonly<Record<string, string>> = Object.freeze(
  Object.fromEntries(
    [...CORE_IDENTITY_PURPOSES.filter((p) => p !== 'app'), 'mutation', 'session'].map((name) => [
      name,
      `metanet:purpose:${name}:v1`,
    ]),
  ),
);

/**
 * Which curve each identity-level purpose's key lives on (selects the
 * verification key AND the circuit's curveTag). Pinned to
 * `IDENTITY_PURPOSE_CURVES` in identityCircomSpec.js: BSV/content/mutation
 * are secp256k1 signing keys; KDA and ICP are Ed25519. `session` keys are
 * secp256k1 (same gadget as mutation).
 */
export const IDENTITY_PURPOSE_CURVES: Readonly<Record<string, CurveName>> = Object.freeze({
  mutation: 'Secp256k1',
  bsv: 'Secp256k1',
  content: 'Secp256k1',
  kda: 'Ed25519',
  icp: 'Ed25519',
  session: 'Secp256k1',
});

/**
 * Per-asset purposes (label bakes the asset id) that carry a Groth16 proof.
 * ALL are secp256k1 (`ASSET_PURPOSE_CURVES` in identityCircomSpec.js).
 * `chatKem` (ML-KEM-768) is deliberately ABSENT: it has no Groth16 proof —
 * it binds to the identity via a mutation-key ECDSA endorsement only.
 */
export const ASSET_PURPOSE_CURVES: Readonly<Record<string, CurveName>> = Object.freeze({
  apps: 'Secp256k1',
  username: 'Secp256k1',
  chat: 'Secp256k1',
  app: 'Secp256k1',
});

/**
 * Build a per-asset purpose label, byte-identical to
 * `ASSET_PURPOSE_LABEL_BUILDERS_V1` in identityCircomSpec.js:
 *
 *   apps     → `metanet:purpose:apps:<appId>:v1`
 *   username → `metanet:purpose:username:<username>:v1`
 *   chat     → `metanet:purpose:chat:<username>:e<epoch>:v1`  (epoch ≥ 1 int)
 *   app      → `metanet:purpose:app:<assetId>:v1`
 *
 * The `id` is used VERBATIM (no normalization) — for `app` proofs it is the
 * envelope's `assetId` (`hash160(appUrl)` or `<appId>:<hash160(salt)>`).
 * The chat label bakes a rotation `epoch` so chat keys are revocable without
 * rotating the identity; the strict positive-integer normalization matches
 * the platform's `chatEpochOrThrow` byte-for-byte.
 */
export function assetPurposeLabel(type: string, id: string, epoch?: number | string): string {
  if (typeof id !== 'string' || id.length === 0) {
    throw new Error(`asset purpose id required for ${type}`);
  }
  switch (type) {
    case 'apps':
      return `metanet:purpose:apps:${id}:v1`;
    case 'username':
      return `metanet:purpose:username:${id}:v1`;
    case 'chat': {
      const n = Number(epoch);
      if (!Number.isInteger(n) || n < 1) {
        throw new Error(`chat purpose requires positive integer epoch (got ${String(epoch)})`);
      }
      return `metanet:purpose:chat:${id}:e${String(n)}:v1`;
    }
    case 'app':
      return `metanet:purpose:app:${id}:v1`;
    default:
      throw new Error(`unknown asset purpose type: ${type}`);
  }
}

/* ------------------------------------------------------------------ *
 * Field / hash helpers.
 * ------------------------------------------------------------------ */

/** Reduce any bigint-coercible value into the BN254 field. Mirrors `asField` in identityCircomSpec.js. */
export function asField(value: bigint | number | string): bigint {
  return BigInt(value) % FIELD_MODULUS;
}

/** labelToField results are stable per process — cache them (labels are a tiny closed set). */
const labelFieldCache = new Map<string, bigint>();

/**
 * Map a purpose/namespace label string to its circuit field element:
 * `poseidon1([ BE-bigint(sha256(utf8(label))) mod p ]) mod p`.
 *
 * WHY this two-step layout: sha256 compresses the arbitrary-length label into
 * 32 bytes; the Poseidon wrap puts the value into the same algebraic hash
 * family as every other circuit input (cheap in-circuit, and domain-uniform).
 * Byte-identical to `labelToField` in identityCircomSpec.js.
 */
export function labelToField(label: string): bigint {
  if (typeof label !== 'string' || label.length === 0) {
    throw new Error('label must be a non-empty string');
  }
  const cached = labelFieldCache.get(label);
  if (cached !== undefined) return cached;
  const digest = sha256(utf8ToBytes(label));
  let n = 0n;
  for (const byte of digest) n = (n << 8n) + BigInt(byte);
  const out = poseidon1([n % FIELD_MODULUS]) % FIELD_MODULUS;
  labelFieldCache.set(label, out);
  return out;
}

/**
 * Decode a compressed public key hex string into the 33 byte-signals the
 * circuit consumes: strict length per curve (secp256k1 = 33-byte SEC1
 * compressed; Ed25519 = 32 bytes), right-padded with zeros to 33.
 *
 * WHY strict: the leafHash commits to EXACTLY these 33 signals — accepting an
 * uncompressed or truncated key would make the verifier hash a statement the
 * prover never proved. Mirrors `paddedPublicKeyBytes` in identityZkVerifier.js.
 */
export function paddedPublicKeyBytes(pubHex: string, curve: CurveName): number[] {
  const clean = String(pubHex ?? '').replace(/^0x/i, '');
  if (!/^[0-9a-f]*$/i.test(clean) || clean.length % 2 !== 0) {
    throw new Error('invalid hex bytes');
  }
  const bytes: number[] = [];
  for (let i = 0; i < clean.length; i += 2) bytes.push(parseInt(clean.slice(i, i + 2), 16));
  const expected = curve === 'Ed25519' ? 32 : 33;
  if (bytes.length !== expected) {
    throw new Error(`${curve} public key must be ${expected} bytes`);
  }
  while (bytes.length < PUBLIC_KEY_SIGNAL_BYTES) bytes.push(0);
  return bytes;
}

/**
 * Poseidon commitment to a purpose public key.
 *
 * Layout (byte-identical to `computePubCommit` in identityCircomSpec.js):
 *   acc = poseidon6([DOMAIN_PUB_COMMIT, purposeTag, curveTag, b0, b1, b2]) mod p
 *   for i in 3..32: acc = poseidon2([acc, b_i]) mod p
 *
 * WHY a fold instead of one wide hash: Poseidon arity is bounded; the head
 * absorbs the domain + tags + first bytes, then a 2-ary sponge folds the
 * remaining 30 byte-signals. Returns the DECIMAL string form used everywhere
 * on the wire.
 */
export function computePubCommit(args: {
  purposeTag: bigint | string;
  curveTag: bigint | number;
  publicKeyBytes: number[];
}): string {
  const { purposeTag, curveTag, publicKeyBytes } = args;
  if (!Array.isArray(publicKeyBytes) || publicKeyBytes.length !== PUBLIC_KEY_SIGNAL_BYTES) {
    throw new Error(`publicKeyBytes must contain exactly ${PUBLIC_KEY_SIGNAL_BYTES} bytes`);
  }
  for (const value of publicKeyBytes) {
    if (!Number.isInteger(value) || value < 0 || value > 255) {
      throw new Error('publicKeyBytes contains a non-byte value');
    }
  }
  let acc =
    poseidon6([
      DOMAIN_PUB_COMMIT,
      asField(purposeTag),
      asField(curveTag),
      asField(publicKeyBytes[0]!),
      asField(publicKeyBytes[1]!),
      asField(publicKeyBytes[2]!),
    ]) % FIELD_MODULUS;
  for (let index = 3; index < PUBLIC_KEY_SIGNAL_BYTES; index += 1) {
    acc = poseidon2([acc, asField(publicKeyBytes[index]!)]) % FIELD_MODULUS;
  }
  return String(acc);
}

/**
 * The circuit's single public signal: the leaf hash binding
 * (seedCommitment, purposeTag, curveTag, pubCommit, circuit version) under
 * the leaf domain. Byte-identical to `computeLeafHash` in identityCircomSpec.js.
 *
 * There is NO merkle tree: each purpose's Groth16 proof stands alone against
 * its own [leafHash]; identity ownership is established by all purposes
 * committing to the SAME seedCommitment (and thus the same canonicalId).
 */
export function computeLeafHash(args: {
  seedCommitment: bigint | string;
  purposeTag: bigint | string;
  curveTag: bigint | number;
  pubCommit: bigint | string;
}): string {
  const { seedCommitment, purposeTag, curveTag, pubCommit } = args;
  return String(
    poseidon6([
      DOMAIN_LEAF,
      asField(seedCommitment),
      asField(purposeTag),
      asField(curveTag),
      asField(pubCommit),
      IDENTITY_ZK_VERSION,
    ]) % FIELD_MODULUS,
  );
}

/* ------------------------------------------------------------------ *
 * canonicalId codec (decode side only — the SDK verifies, it never mints).
 * ------------------------------------------------------------------ */

/**
 * Bitcoin base58 alphabet (no 0/O/I/l). The same alphabet BSV — and
 * essentially every base58 in the multibase spec — uses; canonicalIds are
 * rendered in it with hyphen grouping for scannability.
 */
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_INDEX = new Map<string, number>(
  [...BASE58_ALPHABET].map((c, i) => [c, i] as const),
);

/**
 * Decode a base58 string to bytes. Leading '1' characters map to leading
 * zero bytes (standard base58 convention — preserves byte-length symmetry).
 * Throws on any character outside the Bitcoin alphabet.
 * Byte-identical to `base58Decode` in identityCircomSpec.js.
 */
export function base58Decode(str: string): Uint8Array {
  let zeros = 0;
  while (zeros < str.length && str[zeros] === '1') zeros += 1;
  let num = 0n;
  for (const c of str) {
    const v = BASE58_INDEX.get(c);
    if (v === undefined) throw new Error(`invalid base58 char: ${c}`);
    num = num * 58n + BigInt(v);
  }
  const tail: number[] = [];
  while (num > 0n) {
    tail.unshift(Number(num & 0xffn));
    num >>= 8n;
  }
  return Uint8Array.from([...new Array<number>(zeros).fill(0), ...tail]);
}

/**
 * Decode a V1 identity canonicalId into its Poseidon seedCommitment (decimal
 * string) — the "common anchor" every purpose proof commits to.
 *
 * Steps (byte-identical to `decodeIdentityCanonicalId` + `bytesToField` in
 * identityCircomSpec.js):
 *   1. strip the display hyphens;
 *   2. base58-decode → MUST be exactly 33 bytes;
 *   3. byte[0] MUST be the V1 version byte 0x01 (V0 legacy ids use 0x00 and
 *      are NOT ZK identities — decoding them here must fail, not "work");
 *   4. bytes[1..33] as a big-endian bigint MUST be < FIELD_MODULUS.
 */
export function decodeIdentityCanonicalId(canonicalId: string): string {
  const stripped = String(canonicalId ?? '').replace(/-/g, '');
  if (!stripped) throw new Error('identity canonical id is empty');
  const payload = base58Decode(stripped);
  if (payload.length !== 33) throw new Error('identity canonical id payload must be 33 bytes');
  if (payload[0] !== IDENTITY_CANONICAL_ID_VERSION_BYTE) {
    throw new Error('unsupported identity canonical id version');
  }
  let value = 0n;
  for (let i = 1; i < payload.length; i += 1) value = (value << 8n) + BigInt(payload[i]!);
  if (value >= FIELD_MODULUS) {
    throw new Error('identity canonical id field is outside BN254 modulus');
  }
  return value.toString();
}
