/**
 * shuriken-sdk — embedded, SHA-pinned Groth16 verification keys.
 *
 * WHAT: the two ceremony verification keys for the `metanet-zk-identity-v1`
 *       circuit (one per public-key curve variant: Secp256k1 and Ed25519),
 *       embedded as EXACT byte-for-byte copies of the canonical platform files
 *       (metanet_back/zk/identity/identity_<curve>_verification_key.json),
 *       plus `getVerifiedVkey`, the ONLY sanctioned way to read them.
 * WHY:  a proof verifier is only as trustworthy as its verifying key. If a
 *       compromised build/bundle step swapped one of these strings for a key
 *       from a malicious ceremony, every forged proof would "verify". So the
 *       SDK pins the SHA-256 of each embedded string to the SAME digests the
 *       platform backend and the vault enforce over the canonical files, and
 *       re-hashes at first use: any mismatch throws `ERR_VKEY_INTEGRITY` and
 *       NOTHING verifies (fail closed — a tampered build must not be able to
 *       declare proofs valid).
 *
 * The strings are the raw file contents, NOT reformatted/prettified — the pin
 * is over the exact bytes, so even an innocent re-indent would (correctly)
 * trip the integrity check. Regenerate only by re-copying the canonical files.
 */

import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { NinjaError } from '../errors';

/** The curve variants the identity circuit ships verification keys for. */
export type VkeyCurve = 'Secp256k1' | 'Ed25519';

/**
 * A parsed snarkjs Groth16 verification key (the subset the verifier reads).
 * `nPublic` is 1 for this circuit — the single `leafHash` public signal —
 * so `IC` always has exactly 2 entries (IC[0] + leafHash·IC[1] = vk_x).
 */
export interface Groth16Vkey {
  protocol: string;
  curve: string;
  nPublic: number;
  vk_alpha_1: string[];
  vk_beta_2: string[][];
  vk_gamma_2: string[][];
  vk_delta_2: string[][];
  IC: string[][];
}

/**
 * Pinned SHA-256 digests (hex) of the embedded vkey strings — the SAME pins
 * the platform backend (identityZkVerifier) and the vault enforce over the
 * canonical `metanet_back/zk/identity/*.json` files. Verified at embed time
 * (2026-07-08) against those files byte-for-byte.
 */
export const VKEY_SHA256: Readonly<Record<VkeyCurve, string>> = Object.freeze({
  Secp256k1: '698fe8a75ecebe1f35fc71901ff845255be17aa04bd7308691428a7495ab1916',
  Ed25519: '1789e6c3d6f3a6900140c8600410a30d14b49db321137397ea75580c358648bd',
});

/**
 * The embedded vkey file contents, byte-for-byte. Kept as STRINGS (not parsed
 * objects) so the integrity hash is computed over exactly what was pinned —
 * JSON.parse/stringify round-trips do not preserve bytes.
 */
const VKEY_JSON: Readonly<Record<VkeyCurve, string>> = Object.freeze({
  Secp256k1: "{\n \"protocol\": \"groth16\",\n \"curve\": \"bn128\",\n \"nPublic\": 1,\n \"vk_alpha_1\": [\n  \"20491192805390485299153009773594534940189261866228447918068658471970481763042\",\n  \"9383485363053290200918347156157836566562967994039712273449902621266178545958\",\n  \"1\"\n ],\n \"vk_beta_2\": [\n  [\n   \"6375614351688725206403948262868962793625744043794305715222011528459656738731\",\n   \"4252822878758300859123897981450591353533073413197771768651442665752259397132\"\n  ],\n  [\n   \"10505242626370262277552901082094356697409835680220590971873171140371331206856\",\n   \"21847035105528745403288232691147584728191162732299865338377159692350059136679\"\n  ],\n  [\n   \"1\",\n   \"0\"\n  ]\n ],\n \"vk_gamma_2\": [\n  [\n   \"10857046999023057135944570762232829481370756359578518086990519993285655852781\",\n   \"11559732032986387107991004021392285783925812861821192530917403151452391805634\"\n  ],\n  [\n   \"8495653923123431417604973247489272438418190587263600148770280649306958101930\",\n   \"4082367875863433681332203403145435568316851327593401208105741076214120093531\"\n  ],\n  [\n   \"1\",\n   \"0\"\n  ]\n ],\n \"vk_delta_2\": [\n  [\n   \"12319776827858128227834438549562503804067349984321451839544198645808392953690\",\n   \"206761318745492525030682081384656294303938885313574328034135959666081106598\"\n  ],\n  [\n   \"20858992058663335539327161927138844342835374388212775155316989393316836338088\",\n   \"19397578824287071500313052480462086871967395785852008932188224120743647375775\"\n  ],\n  [\n   \"1\",\n   \"0\"\n  ]\n ],\n \"vk_alphabeta_12\": [\n  [\n   [\n    \"2029413683389138792403550203267699914886160938906632433982220835551125967885\",\n    \"21072700047562757817161031222997517981543347628379360635925549008442030252106\"\n   ],\n   [\n    \"5940354580057074848093997050200682056184807770593307860589430076672439820312\",\n    \"12156638873931618554171829126792193045421052652279363021382169897324752428276\"\n   ],\n   [\n    \"7898200236362823042373859371574133993780991612861777490112507062703164551277\",\n    \"7074218545237549455313236346927434013100842096812539264420499035217050630853\"\n   ]\n  ],\n  [\n   [\n    \"7077479683546002997211712695946002074877511277312570035766170199895071832130\",\n    \"10093483419865920389913245021038182291233451549023025229112148274109565435465\"\n   ],\n   [\n    \"4595479056700221319381530156280926371456704509942304414423590385166031118820\",\n    \"19831328484489333784475432780421641293929726139240675179672856274388269393268\"\n   ],\n   [\n    \"11934129596455521040620786944827826205713621633706285934057045369193958244500\",\n    \"8037395052364110730298837004334506829870972346962140206007064471173334027475\"\n   ]\n  ]\n ],\n \"IC\": [\n  [\n   \"21746311771796892891130053657085319535951210415847923679992728337119995607108\",\n   \"2388046416618066945261419022517027961037868231545615898650814192937948791257\",\n   \"1\"\n  ],\n  [\n   \"19100332650222567181388264078891549479091688893955792640519104948241801562557\",\n   \"1214637946579919394134604649334659553858125489582798527423274641101015779199\",\n   \"1\"\n  ]\n ]\n}",
  Ed25519: "{\n \"protocol\": \"groth16\",\n \"curve\": \"bn128\",\n \"nPublic\": 1,\n \"vk_alpha_1\": [\n  \"20491192805390485299153009773594534940189261866228447918068658471970481763042\",\n  \"9383485363053290200918347156157836566562967994039712273449902621266178545958\",\n  \"1\"\n ],\n \"vk_beta_2\": [\n  [\n   \"6375614351688725206403948262868962793625744043794305715222011528459656738731\",\n   \"4252822878758300859123897981450591353533073413197771768651442665752259397132\"\n  ],\n  [\n   \"10505242626370262277552901082094356697409835680220590971873171140371331206856\",\n   \"21847035105528745403288232691147584728191162732299865338377159692350059136679\"\n  ],\n  [\n   \"1\",\n   \"0\"\n  ]\n ],\n \"vk_gamma_2\": [\n  [\n   \"10857046999023057135944570762232829481370756359578518086990519993285655852781\",\n   \"11559732032986387107991004021392285783925812861821192530917403151452391805634\"\n  ],\n  [\n   \"8495653923123431417604973247489272438418190587263600148770280649306958101930\",\n   \"4082367875863433681332203403145435568316851327593401208105741076214120093531\"\n  ],\n  [\n   \"1\",\n   \"0\"\n  ]\n ],\n \"vk_delta_2\": [\n  [\n   \"20956811383675331800635041948443610562939133162683835502129994693920788897146\",\n   \"1481380662259360521984680437152021357323680779265254054740511864562048150186\"\n  ],\n  [\n   \"3269394296721977666138868421703349967784731242635160354305695150139610333897\",\n   \"3624300656208779502167412980442834651865520254932883174854638541338956299517\"\n  ],\n  [\n   \"1\",\n   \"0\"\n  ]\n ],\n \"vk_alphabeta_12\": [\n  [\n   [\n    \"2029413683389138792403550203267699914886160938906632433982220835551125967885\",\n    \"21072700047562757817161031222997517981543347628379360635925549008442030252106\"\n   ],\n   [\n    \"5940354580057074848093997050200682056184807770593307860589430076672439820312\",\n    \"12156638873931618554171829126792193045421052652279363021382169897324752428276\"\n   ],\n   [\n    \"7898200236362823042373859371574133993780991612861777490112507062703164551277\",\n    \"7074218545237549455313236346927434013100842096812539264420499035217050630853\"\n   ]\n  ],\n  [\n   [\n    \"7077479683546002997211712695946002074877511277312570035766170199895071832130\",\n    \"10093483419865920389913245021038182291233451549023025229112148274109565435465\"\n   ],\n   [\n    \"4595479056700221319381530156280926371456704509942304414423590385166031118820\",\n    \"19831328484489333784475432780421641293929726139240675179672856274388269393268\"\n   ],\n   [\n    \"11934129596455521040620786944827826205713621633706285934057045369193958244500\",\n    \"8037395052364110730298837004334506829870972346962140206007064471173334027475\"\n   ]\n  ]\n ],\n \"IC\": [\n  [\n   \"19201867359316562913634822830159448038572680477597760486125355297304021078613\",\n   \"8874427525437651666355237063526576311743215655981250172886196492315609524476\",\n   \"1\"\n  ],\n  [\n   \"14331095441412941598368587624600030018789653590676675103298935045715833285637\",\n   \"9462942874631889629788777268629587303081982603048957602751688808441697443663\",\n   \"1\"\n  ]\n ]\n}",
});

/** Parsed-vkey cache: hash once, parse once, reuse forever (per curve). */
const parsedCache = new Map<VkeyCurve, Groth16Vkey>();

/**
 * Return the parsed Groth16 verification key for `curve`, after proving the
 * embedded bytes still hash to the pinned digest.
 *
 * WHAT: sha256(utf8 bytes of the embedded string) must equal
 *       `VKEY_SHA256[curve]`; on match the string is JSON.parsed once and
 *       cached; on mismatch throws `NinjaError('ERR_VKEY_INTEGRITY')`.
 * WHY:  fail closed. A verifier that silently ran with a substituted key would
 *       accept forged proofs — the worst possible failure mode — so integrity
 *       failure is a hard, typed error, never a boolean `false`.
 */
export function getVerifiedVkey(curve: VkeyCurve): Groth16Vkey {
  const cached = parsedCache.get(curve);
  if (cached) return cached;

  const embedded = VKEY_JSON[curve];
  const pin = VKEY_SHA256[curve];
  if (typeof embedded !== 'string' || typeof pin !== 'string') {
    // Unknown curve name: same failure class as a tampered key — refuse.
    throw new NinjaError('ERR_VKEY_INTEGRITY', {
      hint: `no embedded verification key for curve '${String(curve)}'`,
    });
  }

  const digest = bytesToHex(sha256(utf8ToBytes(embedded)));
  if (digest !== pin) {
    throw new NinjaError('ERR_VKEY_INTEGRITY', {
      hint: `${curve} verification key failed its SHA-256 pin (got ${digest}); the SDK bundle is corrupted or tampered — refuse to verify`,
    });
  }

  const parsed = JSON.parse(embedded) as Groth16Vkey;
  parsedCache.set(curve, parsed);
  return parsed;
}

/**
 * TEST SEAM — verify an arbitrary candidate string against a pin, without
 * touching the cache. Lets the test suite prove a byte-flip in the embedded
 * string would throw `ERR_VKEY_INTEGRITY`, exercising the exact same
 * hash-compare the production path uses.
 */
export function assertVkeyIntegrity(candidate: string, pinnedSha256Hex: string, curveLabel = 'candidate'): void {
  const digest = bytesToHex(sha256(utf8ToBytes(candidate)));
  if (digest !== pinnedSha256Hex) {
    throw new NinjaError('ERR_VKEY_INTEGRITY', {
      hint: `${curveLabel} verification key failed its SHA-256 pin (got ${digest})`,
    });
  }
}
