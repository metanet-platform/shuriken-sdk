/**
 * shuriken-sdk — Poseidon hash primitives (BN254) for proof verification.
 *
 * WHAT: re-exports the three Poseidon arities the identity circuit uses —
 *       `poseidon1` (label hashing), `poseidon2` (pubCommit fold), `poseidon6`
 *       (pubCommit head + leafHash) — from `poseidon-lite` SUBPATH imports.
 * WHY:  subpath imports (`poseidon-lite/poseidon1` etc.) pull in ONLY the
 *       round constants for the arities we use, keeping the inlined bundle
 *       lean (the barrel `poseidon-lite` import would drag all 16 constant
 *       tables in). `poseidon-lite` is a devDependency inlined at build via
 *       tsup `noExternal` — exactly like `@noble/*` — so the published package
 *       keeps ZERO runtime dependencies.
 *
 * These are the SAME functions (same package, same constants) the platform
 * backend (metanet_back/src/services/identityCircomSpec.js) and the vault
 * prover use, so hashes agree bit-for-bit across the whole system.
 */

import { poseidon1 } from 'poseidon-lite/poseidon1';
import { poseidon2 } from 'poseidon-lite/poseidon2';
import { poseidon6 } from 'poseidon-lite/poseidon6';

export { poseidon1, poseidon2, poseidon6 };
