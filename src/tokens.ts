/**
 * shuriken-sdk — named ICP ledger aliases.
 *
 * WHAT: a small, frozen map of human-friendly token names (`ICP`, `ckUSDC`,
 *       `ckBTC`, …) to their canonical ICP ledger canister ids, plus
 *       `resolveLedger(nameOrId)` which turns an alias into an id (or passes a
 *       raw id straight through).
 * WHY:  the hand-copied SDKs hardcoded raw canister ids at every `pay.icp(...)`
 *       call site, so a single ledger-id typo silently sent tokens into the void
 *       and each copy drifted its own way. Centralizing the alias table here — the
 *       ONE place a canister id is written — means callers say `pay.icp({ token:
 *       'ckUSDC' })` and can never fat-finger a 27-char principal. Unknown aliases
 *       are NOT silently accepted: `resolveLedger` only rewrites known names and
 *       otherwise passes the input through, so an unknown token surfaces as the
 *       parent's `ERR_UNSUPPORTED_TOKEN` rather than a mis-send.
 *
 * This module has ZERO dependencies and no runtime cost beyond an object lookup.
 */

/**
 * Canonical ICP ledger canister ids, keyed by their well-known token symbol.
 *
 * WHAT: `Readonly<Record<string, string>>` — symbol → ledger canister id.
 * WHY:  `Readonly` + `as const` freeze the table so no caller can mutate the
 *       shared map (a mutation here would corrupt every subsequent resolve). The
 *       ids are the mainnet NNS/ck* ledgers; keeping them in one audited constant
 *       is what lets `pay.icp` stay id-free at the call site.
 *
 * TODO(v1.0): confirm every canister id against the live ledgers before the 1.0
 * cut (BUILD_SPEC: "Confirm ids before v1.0"). The four below are the mainnet
 * NNS ICP ledger and the ck-asset ledgers currently wired in the platform.
 */
export const tokens: Readonly<Record<string, string>> = {
  /** The native ICP token (NNS ledger). */
  ICP: 'ryjl3-tyaaa-aaaaa-aaaba-cai',
  /** ck-USDC (Chain-Key USDC) ledger. */
  ckUSDC: 'xevnm-gaaaa-aaaar-qafnq-cai',
  /** ck-BTC (Chain-Key Bitcoin) ledger. */
  ckBTC: 'mxzaz-hqaaa-aaaar-qaada-cai',
  /** ck-ETH (Chain-Key Ether) ledger. */
  ckETH: 'ss2fx-dyaaa-aaaar-qacoq-cai',
} as const;

/**
 * Resolve a token alias (or a raw ledger id) to a canister id.
 *
 * WHAT: if `nameOrId` is a known alias in {@link tokens}, returns its canister
 *       id; otherwise returns `nameOrId` unchanged (passthrough).
 * WHY:  callers may pass either the friendly symbol (`'ckUSDC'`) or, for a token
 *       we don't yet alias, the raw canister id itself. A pure alias→id lookup
 *       with passthrough covers both without a second code path, and crucially it
 *       does NOT throw on an unknown token: forwarding the raw value lets the
 *       parent be the single authority on which ledgers exist (it answers with
 *       `ERR_UNSUPPORTED_TOKEN`), rather than the SDK guessing and rejecting a
 *       ledger that is actually valid but simply not in this table yet.
 *
 * @param nameOrId a token symbol (`'ICP'`, `'ckUSDC'`, …) or a raw ledger id.
 * @returns the resolved canister id (or `nameOrId` verbatim if not an alias).
 */
export function resolveLedger(nameOrId: string): string {
  // Object lookup: a known alias rewrites to its id; anything else falls through
  // unchanged so a raw canister id (or a not-yet-aliased token) is preserved.
  return tokens[nameOrId] ?? nameOrId;
}
