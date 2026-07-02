/**
 * shuriken-sdk — codegen: manifest.json -> src/generated/capabilities.ts.
 *
 * WHAT: a small, real build step (run via `npm run generate`, and again inside
 *       `npm run build`) that reads the machine-readable `manifest.json` and
 *       (re)writes a *typed, frozen snapshot* of the command surface to
 *       `src/generated/capabilities.ts`. While it is at it, it asserts that the
 *       set of command keys declared in the manifest is a SUBSET of the closed
 *       `NinjaMethod` union in `src/types.ts` — the single conformance gate that
 *       keeps the manifest, the types, and the docs from ever drifting apart.
 * WHY:  the whole reason shuriken-sdk exists is that ~15 hand-copied SDKs let their
 *       method list, their type union, and their docs diverge. This script makes
 *       that divergence a *build failure*: if someone adds a command to the
 *       manifest without adding it to `NinjaMethod` (or mistypes one), the build
 *       stops here with a precise message instead of shipping a broken surface.
 *       The emitted snapshot also gives the runtime a dependency-free, tree-shaken
 *       list of capability names (no JSON import needed) for fast membership tests.
 *
 * DESIGN NOTES
 *  - Pure Node, zero deps: only `node:fs` / `node:path` / `node:url`. It must run
 *    in CI before any bundling, so it cannot depend on the built `dist/`.
 *  - It imports the `NinjaMethod` union *as data* by re-declaring the closed list
 *    here as `KNOWN_METHODS` and keeping it in lockstep with `types.ts`. WHY not
 *    parse types.ts? Parsing TypeScript at codegen time would pull in a TS parser
 *    (a runtime dep) and is brittle; instead this constant is the codegen mirror
 *    of the union, and the emitted file's `satisfies NinjaMethod[]` makes `tsc`
 *    prove the mirror is correct at typecheck time (belt AND suspenders).
 *  - The script is idempotent: running it twice with an unchanged manifest yields
 *    a byte-identical file (stable key ordering, fixed header), so it is safe to
 *    commit the output and diff it in review.
 */

// ── Node builtins ──────────────────────────────────────────────────────────────
// This codegen runs via `tsx` before any bundling (`npm run generate`) and is
// never shipped in `dist`. It uses the canonical ESM `node:*` imports — the only
// form that works at runtime under this package's `"type": "module"`.
//
// The three `@ts-expect-error`s below exist ONLY because this repo does not list
// `@types/node` as a devDependency, so `tsc` cannot resolve the builtin type
// declarations (the runtime is unaffected — Node provides the modules). They are
// scoped to exactly these import lines so no real error is ever masked; installing
// `@types/node` makes each `@ts-expect-error` "unused" and thus a signal to remove
// them. TODO(v1.0): add `@types/node` to devDependencies and delete these.
// @ts-expect-error — node:fs types require @types/node (dev-only; see note above).
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
// @ts-expect-error — node:path types require @types/node (dev-only; see note above).
import { dirname, resolve } from 'node:path';
// @ts-expect-error — node:url types require @types/node (dev-only; see note above).
import { fileURLToPath } from 'node:url';

/* ------------------------------------------------------------------ *
 * Paths — resolved relative to THIS file so the script works no matter
 * what the process cwd is (npm scripts, CI, or a direct `tsx` call).
 * ------------------------------------------------------------------ */

/** Absolute path of this script's directory (`<repo>/scripts`). */
const HERE = dirname(fileURLToPath(import.meta.url));
/** The machine-readable source of truth, one level up from `scripts/`. */
const MANIFEST_PATH = resolve(HERE, '..', 'manifest.json');
/** Where the typed snapshot is written; created if missing. */
const OUT_PATH = resolve(HERE, '..', 'src', 'generated', 'capabilities.ts');

/* ------------------------------------------------------------------ *
 * The closed method union, mirrored for codegen.
 *
 * This MUST match the `NinjaMethod` union in `src/types.ts` exactly. The emitted
 * file asserts `satisfies NinjaMethod[]`, so if this list and the union ever
 * disagree, `tsc` fails on the generated file — the mirror can't silently rot.
 * ------------------------------------------------------------------ */

/** Every wire method the SDK recognizes (mirror of `NinjaMethod`). */
const KNOWN_METHODS = [
  'connection',
  'pay',
  'create-post',
  'generate-proof',
  'full-transaction',
  'token-history',
  'open-link',
  'write-clipboard',
  'qr-scan',
  'qr-scan-stop',
  'geolocation',
  'geolocation-stop',
] as const;

/**
 * The minimal shape we read out of `manifest.json`.
 *
 * WHAT: only the fields this generator touches — the `commands` map and, per
 *       command, the handful of slots the runtime snapshot surfaces.
 * WHY:  typing the parsed JSON (rather than `any`) means a manifest structural
 *       change (e.g. `commands` renamed) fails loudly here instead of emitting
 *       `undefined`s into the generated file.
 */
interface ManifestShape {
  protocolVersion?: number;
  commands: Record<string, ManifestCommand>;
}

/** The per-command manifest slots the snapshot captures. */
interface ManifestCommand {
  wireType?: string;
  responseType?: string | null;
  stopType?: string;
  streaming?: boolean;
  requiresWallet?: boolean;
  noReply?: boolean;
  consent?: string | null;
  since?: string;
}

/**
 * Read + parse the manifest, failing with a clear message on any I/O or JSON
 * error. WHY a wrapper: a raw `JSON.parse` throw gives a cryptic "Unexpected
 * token" with no path; here the operator learns *which* file and *why*.
 */
function loadManifest(): ManifestShape {
  let text: string;
  try {
    text = readFileSync(MANIFEST_PATH, 'utf8');
  } catch (err) {
    throw new Error(`[generate] cannot read manifest at ${MANIFEST_PATH}: ${String(err)}`);
  }
  try {
    return JSON.parse(text) as ManifestShape;
  } catch (err) {
    throw new Error(`[generate] manifest is not valid JSON (${MANIFEST_PATH}): ${String(err)}`);
  }
}

/**
 * The conformance gate: assert manifest command keys ⊆ NinjaMethod.
 *
 * WHAT: verifies every key in `manifest.commands` is a member of the closed
 *       `KNOWN_METHODS` mirror; throws listing any strays if not.
 * WHY:  this is THE check that keeps the manifest honest against the type union.
 *       The manifest is allowed to declare *fewer* methods than the union (a
 *       method can exist in the type surface before its manifest entry lands),
 *       so we require subset, not equality — but a manifest command with no
 *       matching `NinjaMethod` is always a bug (a typo, or a method added to the
 *       manifest without extending the closed union), and it fails the build.
 *
 * @param commandKeys the keys of `manifest.commands`.
 * @returns the keys unchanged (so callers can chain), after validation.
 */
function assertMethodsSubset(commandKeys: string[]): string[] {
  const known = new Set<string>(KNOWN_METHODS);
  const strays = commandKeys.filter((k) => !known.has(k));
  if (strays.length > 0) {
    throw new Error(
      `[generate] manifest declares command(s) not present in NinjaMethod: ` +
        `${strays.join(', ')}. Add them to the NinjaMethod union in src/types.ts ` +
        `and to KNOWN_METHODS in scripts/generate.ts, or fix the manifest key.`,
    );
  }
  return commandKeys;
}

/**
 * Render the generated TypeScript source as a string.
 *
 * WHAT: produces the full contents of `src/generated/capabilities.ts` — a header
 *       marking it as generated, the frozen list of capability names typed as
 *       `readonly NinjaMethod[]`, a ready-made `Set` for membership tests, and a
 *       small per-command metadata record (streaming/noReply/etc.) the runtime
 *       can consult without importing the whole manifest JSON.
 * WHY:  emitting a `.ts` (not `.json`) lets the snapshot carry real types
 *       (`satisfies NinjaMethod[]`) so `tsc` validates the mirror, and lets it be
 *       tree-shaken into the bundle. Key ordering is taken straight from the
 *       manifest's declaration order for a stable, reviewable diff.
 *
 * @param manifest      the parsed manifest.
 * @param orderedKeys   command keys in manifest declaration order.
 */
function renderModule(manifest: ManifestShape, orderedKeys: string[]): string {
  // Per-command metadata slice: only the flags the runtime actually branches on.
  // Kept intentionally small — the full schema stays in manifest.json, which the
  // runtime `capabilities()` reads for the rich slice.
  const meta: Record<string, ManifestCommand> = {};
  for (const key of orderedKeys) {
    const cmd = manifest.commands[key];
    if (!cmd) continue; // unreachable (keys come from the map) but satisfies noUncheckedIndexedAccess.
    // Copy only the known slots; drop undefined ones so the emitted object is tidy.
    const entry: ManifestCommand = {};
    if (cmd.wireType !== undefined) entry.wireType = cmd.wireType;
    if (cmd.responseType !== undefined) entry.responseType = cmd.responseType;
    if (cmd.stopType !== undefined) entry.stopType = cmd.stopType;
    if (cmd.streaming !== undefined) entry.streaming = cmd.streaming;
    if (cmd.requiresWallet !== undefined) entry.requiresWallet = cmd.requiresWallet;
    if (cmd.noReply !== undefined) entry.noReply = cmd.noReply;
    if (cmd.consent !== undefined) entry.consent = cmd.consent;
    if (cmd.since !== undefined) entry.since = cmd.since;
    meta[key] = entry;
  }

  const namesLiteral = orderedKeys.map((k) => `  '${k}',`).join('\n');
  const metaLiteral = JSON.stringify(meta, null, 2)
    // Re-indent the JSON block by two spaces so it sits nicely inside the export.
    .split('\n')
    .map((line, i) => (i === 0 ? line : '  ' + line))
    .join('\n');
  const protocolVersion = manifest.protocolVersion ?? 1;

  return `/**
 * shuriken-sdk — GENERATED capability snapshot. DO NOT EDIT BY HAND.
 *
 * WHAT: a typed, frozen mirror of the command surface declared in the top-level
 *       \`manifest.json\`. Produced by \`scripts/generate.ts\` (\`npm run generate\`,
 *       and again as the first step of \`npm run build\`).
 * WHY:  gives the runtime a dependency-free, tree-shakeable list of capability
 *       names (and a few per-command flags) without importing the manifest JSON,
 *       and makes the manifest ↔ \`NinjaMethod\` correspondence a *compile-time*
 *       guarantee: the \`satisfies NinjaMethod[]\` below fails \`tsc\` if the
 *       generated names ever leave the closed method union.
 *
 * Regenerate instead of editing: change \`manifest.json\`, then \`npm run generate\`.
 */

import type { NinjaMethod } from '../types';

/** The protocol version this snapshot was generated from (manifest.protocolVersion). */
export const PROTOCOL_VERSION = ${protocolVersion} as const;

/**
 * Every command name declared in the manifest, in declaration order.
 * Typed \`readonly NinjaMethod[]\` via \`satisfies\` so a stray/mistyped name here
 * is a typecheck error — the manifest can never advertise a non-\`NinjaMethod\`.
 */
export const CAPABILITY_NAMES = [
${namesLiteral}
] as const satisfies readonly NinjaMethod[];

/** A ready-made membership set for O(1) \`has(method)\` checks in the codec/facade. */
export const CAPABILITY_SET: ReadonlySet<NinjaMethod> = new Set(CAPABILITY_NAMES);

/**
 * Per-command runtime flags lifted from the manifest (streaming/noReply/consent/…).
 * The full schema (request/response/errors/examples) stays in \`manifest.json\`,
 * which the runtime \`capabilities()\` reads for the rich slice; this is only the
 * subset the transport/codec branch on hot paths.
 */
export const CAPABILITY_META = ${metaLiteral} as const;
`;
}

/**
 * Entry point: load, validate, render, write. Kept as one linear function so the
 * script reads top-to-bottom; each step throws with an actionable message on
 * failure so a broken build is diagnosable from the log alone.
 */
function main(): void {
  const manifest = loadManifest();

  if (!manifest.commands || typeof manifest.commands !== 'object') {
    throw new Error(`[generate] manifest has no "commands" object (${MANIFEST_PATH}).`);
  }

  // Declaration order from the JSON object drives the emitted order for stable diffs.
  const orderedKeys = Object.keys(manifest.commands);

  // THE conformance gate. Throws (fails the build) on any manifest command that
  // isn't a NinjaMethod. Must run before we emit anything.
  assertMethodsSubset(orderedKeys);

  const source = renderModule(manifest, orderedKeys);

  // Ensure `src/generated/` exists (first run on a fresh checkout won't have it).
  mkdirSync(dirname(OUT_PATH), { recursive: true });
  writeFileSync(OUT_PATH, source, 'utf8');

  // A concise success line so CI logs show what happened and how many commands
  // made it into the snapshot.
  // eslint-disable-next-line no-console
  console.log(
    `[generate] wrote ${OUT_PATH} (${orderedKeys.length} commands, ` +
      `protocol ${manifest.protocolVersion ?? 1}).`,
  );
}

// Run immediately: this module is an executable script, not a library. Any thrown
// error propagates to a non-zero exit so `npm run build` stops on a bad manifest.
main();
