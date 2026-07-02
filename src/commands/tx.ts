/**
 * shuriken-sdk — transaction reads (`ninja.tx`).
 *
 * WHAT: `makeTx` builds `{ get(txid), history(params) }` over the
 *       `full-transaction` and `token-history` wire methods.
 * WHY:  these are the two read-only, no-consent data calls. Grouping them under
 *       `tx` keeps SPV fetch (`get`) and paginated history (`history`) discoverable
 *       together, and lets `get` take a bare txid string (the overwhelmingly common
 *       call) instead of forcing callers to build a `{ txid }` object.
 */

import type { Codec } from '../protocol/codec';
import type { FullTransactionResult, TokenHistoryParams, TokenHistoryResult } from '../types';

/**
 * Build the `ninja.tx` sugar object.
 *
 * WHAT: returns `{ get, history }`, thin wrappers over the two read methods.
 * WHY:  `get` wraps the txid into the `{ txid }` param the wire expects so the
 *       ergonomic call is `ninja.tx.get('e3b0…')`; `history` passes its params
 *       through (chain/limit/offset are all optional and the parent applies its
 *       own defaults). Both are wallet-free and consent-free, so no extra
 *       local guarding is required.
 */
export function makeTx(codec: Codec): {
  get(txid: string): Promise<FullTransactionResult>;
  history(params?: TokenHistoryParams): Promise<TokenHistoryResult>;
} {
  return {
    /**
     * Fetch a full BSV transaction for SPV verification.
     *
     * @param txid the transaction id to fetch.
     * @returns raw hex + optional BUMP merkle path (`bumpHex`) for SPV.
     */
    get(txid: string): Promise<FullTransactionResult> {
      return codec.call<FullTransactionResult>('full-transaction', { txid });
    },

    /**
     * Fetch paginated transaction history for a chain.
     *
     * @param params optional chain / limit / offset; the parent defaults chain to
     *               the primary wallet chain and applies its own page size cap.
     * @returns the page of transactions plus `hasMore` / `totalCount`.
     */
    history(params: TokenHistoryParams = {}): Promise<TokenHistoryResult> {
      return codec.call<TokenHistoryResult>('token-history', params);
    },
  };
}
