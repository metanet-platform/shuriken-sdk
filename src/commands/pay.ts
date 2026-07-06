/**
 * shuriken-sdk — `pay` command sugar.
 *
 * WHAT: `makePay` builds the `ninja.pay` object with three chain-specific
 *       methods: `bsv(recipients)`, `icp(params)`, `kda(params)`.
 * WHY:  a single wire method (`pay`) serves three chains that have genuinely
 *       different shapes and invariants (BSV is multi-recipient; ICP/KDA are
 *       single-recipient token transfers). Collapsing them into one untyped
 *       `pay(anything)` is exactly what let the hand-copied SDKs send an ICP
 *       transfer with two recipients and get a confusing platform error. Here
 *       each method enforces its own contract locally (recipient arity, ledger
 *       resolution) and carries its own precise result type.
 *
 * BSV BROADCAST SEMANTICS (the platform's deliberate two-step):
 *       the parent's `pay` overlay returns a SIGNED-BUT-UNBROADCAST raw tx —
 *       the UTXO spend is authorized, nothing is on the network yet. Finalizing
 *       is a separate, app-authenticated HTTP step against the Metanet overlay
 *       (`api.metanet.ninja/data/api`), signed with the session's
 *       `genericUseSeed` (delivered at connect on BOTH V0 and V1). `pay.bsv`
 *       folds that step in behind `{ broadcast }`: `true` (default) finalizes
 *       and resolves the network `txid`; `false` stops after authorization so
 *       the app can inspect / chain / batch and broadcast later.
 */

import type { Codec } from '../protocol/codec';
import { NinjaError } from '../errors';
import { resolveLedger } from '../tokens';
import { broadcastRawTx } from '../broadcast';
import type {
  BsvPayOptions,
  BsvPayResult,
  BsvRecipient,
  IcpPayParams,
  IcpPayResult,
  KdaPayParams,
  KdaPayResult,
} from '../types';

/**
 * Build the `ninja.pay` sugar object.
 *
 * WHAT: returns `{ bsv, icp, kda }`, each a thin typed wrapper over
 *       `codec.call('pay', …)` that shapes the wire params for its chain.
 * WHY:  the parent infers the chain from the params it receives, so the SDK's
 *       job is to construct the exactly-correct param shape per chain and to
 *       reject impossible requests (multiple ICP/KDA recipients) locally with a
 *       precise `ERR_MULTIPLE_RECIPIENTS` rather than paying a 60s round trip to
 *       learn the same thing. `resolveLedger` maps a friendly token alias
 *       (`'ckUSDC'`) to its canister id so callers never hardcode ledger ids.
 *
 * @param codec           the wire engine.
 * @param getBroadcastKey live accessor for the session's `genericUseSeed` (the
 *                        secp256k1 key that authenticates broadcast-API calls).
 *                        A thunk — not a snapshot — because the seed is only
 *                        known after `connect()` and rotates on re-connect/salt.
 */
export function makePay(
  codec: Codec,
  getBroadcastKey: () => string | null,
): {
  bsv(recipients: BsvRecipient[], opts?: BsvPayOptions): Promise<BsvPayResult>;
  icp(params: IcpPayParams): Promise<IcpPayResult>;
  kda(params: KdaPayParams): Promise<KdaPayResult>;
} {
  return {
    /**
     * BSV payment (multi-recipient), with built-in network finalization.
     *
     * WHAT: sends every recipient (sats / usd / fee-only) in one `pay` call; the
     *       parent overlay returns the authorized raw tx. With
     *       `broadcast: true` (the DEFAULT) the SDK then finalizes it — POSTs the
     *       raw tx to the Metanet broadcast API signed with the session's
     *       `genericUseSeed` — and resolves `{ rawTxHex, txid, broadcast: true }`.
     *       With `broadcast: false` it resolves `{ rawTxHex, broadcast: false }`:
     *       UTXOs authorized, nothing on the network.
     * WHY:  a payment should FINALIZE by default (apps forgetting the second step
     *       shipped "payments" that never hit the chain), while the two-step
     *       escape hatch stays first-class for inspect/chain/batch flows —
     *       finish later with `broadcastRawTx(rawTxHex, me.genericUseSeed)`.
     *       Broadcasting without a session key is a hard, precise error
     *       (`ERR_NO_BROADCAST_KEY`) — never a silent skip: a caller who asked
     *       for a broadcast must not believe one happened.
     */
    async bsv(recipients: BsvRecipient[], opts: BsvPayOptions = {}): Promise<BsvPayResult> {
      const broadcast = opts.broadcast ?? true;

      // Map the ergonomic public shape (sats/usd/fee) to the parent's exact wire
      // fields (value/fiatValue/reason) — see toBsvWireRecipients for why.
      const wireRecipients = toBsvWireRecipients(recipients);

      // Fail BEFORE the consent overlay when a broadcast was requested but no
      // session key exists (connect() not called, or the parent sent no seed) —
      // don't make the user approve a payment we already know we can't finalize.
      const key = broadcast ? getBroadcastKey() : null;
      if (broadcast && !key) {
        throw new NinjaError('ERR_NO_BROADCAST_KEY', {
          method: 'pay',
          hint:
            'broadcast:true needs the session genericUseSeed — call ninja.connect() first, ' +
            'or pass { broadcast: false } to get the authorized rawTx without broadcasting.',
        });
      }

      // Step 1 — authorize: the parent shows the consent overlay, signs the tx,
      // and returns the raw hex. The chain is inferred parent-side from the
      // absence of a `token` field; FX (`usd`) and fee-only outputs are parent-handled.
      const payload = await codec.call<BsvPayResult>('pay', { recipients: wireRecipients });

      if (!broadcast) {
        return { ...payload, broadcast: false };
      }

      // Step 2 — finalize: hand the raw tx to the overlay network. broadcastRawTx
      // signs the canonical request with the seed (byte-exact with the backend
      // verifier) and returns the per-tx outcome. A rejection surfaces as a typed
      // ERR_BROADCAST_FAILED carrying the API's reason — the tx is NOT on-chain.
      const outcome = await broadcastRawTx(payload.rawTxHex, key as string, {
        ...(opts.source !== undefined ? { source: opts.source } : {}),
      }).catch((e: unknown) => {
        throw new NinjaError('ERR_BROADCAST_FAILED', {
          method: 'pay',
          hint: e instanceof Error ? e.message : String(e),
          cause: e,
        });
      });
      if (!outcome.success) {
        throw new NinjaError('ERR_BROADCAST_FAILED', {
          method: 'pay',
          hint: outcome.error ?? 'broadcast API reported failure',
        });
      }

      return {
        ...payload,
        broadcast: true,
        ...(outcome.txid !== undefined ? { txid: outcome.txid } : {}),
      };
    },

    /**
     * ICP token transfer (single recipient).
     *
     * WHAT: transfers `amount` of `token` to a principal; resolves the transfer
     *       outcome (a bigint block index / result).
     * WHY:  ICP ledgers accept exactly one recipient per transfer. We express
     *       that as a single-element `recipients` array so the parent's `pay`
     *       handler sees a uniform shape, and we tag `token.protocol: 'ICP'` so
     *       the parent routes to its ICP path. `resolveLedger(params.token)` turns
     *       an alias into a canister id (passthrough if already an id), so an
     *       unknown token surfaces as `ERR_UNSUPPORTED_TOKEN` from the parent
     *       rather than a silent mis-send. `amount` is a decimal in WHOLE token
     *       units (e.g. 1.5 ckUSDC) — NOT base units/e8s. The overlay formats it
     *       via the ledger's decimals and the modal converts to base units; the
     *       SDK forwards it verbatim (no conversion, no bigint).
     */
    icp(params: IcpPayParams): Promise<IcpPayResult> {
      const ledger = resolveLedger(params.token);
      // Build the single-recipient wire params EXACTLY as paymentHandler.js reads
      // them: the parent gates the ICP form on `token.protocol === 'ICP'` AND
      // `token.specification.ledgerId` (paymentHandler.js line 47) — a `token.ledger`
      // sibling is invisible to it, so the request would silently fall through to
      // the BSV form. Each recipient must carry `address` + `value` (line 105); the
      // optional note travels as `note` (line 125 reads `note || reason`).
      const recipient: Record<string, unknown> = { address: params.to, value: params.amount };
      if (params.memo !== undefined) recipient['note'] = params.memo;
      return codec.call<IcpPayResult>('pay', {
        token: { protocol: 'ICP', specification: { ledgerId: ledger } },
        recipients: [recipient],
      });
    },

    /**
     * KDA (Kadena) transfer (single recipient).
     *
     * WHAT: transfers `amount` KDA to `to` on `chainId` (default '2'); resolves
     *       the mempool request key + chain id.
     * WHY:  like ICP, KDA is single-recipient, so we wrap the one recipient in a
     *       one-element array and tag `token.protocol: 'KDA'` for parent routing.
     *       `chainId` defaults to '2' (the platform's canonical funding chain) so
     *       callers who don't care about Kadena's braided chains get a working
     *       default instead of a missing-param error.
     */
    kda(params: KdaPayParams): Promise<KdaPayResult> {
      const chainId = params.chainId ?? '2';
      // Only chain '2' is supported for sending from balance right now (the
      // platform's funding chain). Reject anything else locally with a precise,
      // typed error rather than a confusing parent-side failure. More chains may
      // be supported in a later release.
      if (chainId !== '2') {
        throw new NinjaError('ERR_NOT_SUPPORTED', {
          method: 'pay',
          hint: 'KDA sending currently supports chainId "2" only.',
        });
      }
      // Shape EXACTLY as paymentHandler.js reads it: the KDA form is gated on
      // `token.protocol === 'KDA'` (line 148); the chain id is read from
      // `token.specification.chainId` (line 181), NOT off the recipient; and each
      // recipient must carry `address` + `value` (line 164), with the note under
      // `note` (line 180 reads `note || reason`).
      return codec.call<KdaPayResult>('pay', {
        token: { protocol: 'KDA', specification: { chainId: '2' } },
        recipients: [{ address: params.to, value: params.amount }],
      });
    },
  };
}

/**
 * Map ergonomic `BsvRecipient`s to the parent's exact `pay` wire shape.
 *
 * WHAT: turns each public recipient (`{ address?, sats?, usd?, fiatValue?,
 *       currency?, note?, fee? }`) into the fields `paymentHandler.js` reads:
 *         sats      -> value      (amount in satoshis)
 *         fiatValue -> fiatValue  (amount in fiat; `usd` is the USD shortcut)
 *         currency  -> currency   (fiat currency; platform does the FX)
 *         fee       -> reason     (fee-only recipient: parent resolves SERVICE_FEES)
 *         address   -> address    (pass through)
 *         note      -> note       (pass through)
 *       Only fields that are present are emitted. The SDK never converts amounts —
 *       the platform's form/handler do all sats<->fiat conversion.
 * WHY:  the ergonomic names (`sats`/`usd`/`fee`) are the public SDK API, but the
 *       parent's handler gates a value recipient on `r.value`/`r.fiatValue`
 *       (paymentHandler.js line 215-217) and a fee-only recipient on `r.reason`
 *       (line 206). Forwarding `sats`/`usd`/`fee` verbatim made `r.value` and
 *       `r.fiatValue` both undefined, so the handler hit its `return` at line 218
 *       and SILENTLY DROPPED the recipient — the overlay then had nothing to
 *       pre-fill (empty `transfer_params.recipients`). The mapping must happen in
 *       the SDK because the wire contract is the parent's, not the SDK's, so the
 *       ergonomic shape is translated once here rather than leaking parent field
 *       names into the public type.
 */
export function toBsvWireRecipients(
  recipients: readonly BsvRecipient[],
): Array<Record<string, unknown>> {
  return recipients.map((r) => {
    const wire: Record<string, unknown> = {};
    if (r.address !== undefined) wire['address'] = r.address;
    if (r.sats !== undefined) wire['value'] = r.sats;
    // Fiat: an explicit `fiatValue` (+ optional `currency`) wins; `usd` is the
    // USD shortcut. The SDK does NOT convert — the platform's form/handler do the
    // sats<->fiat conversion using its FX rates.
    if (r.fiatValue !== undefined) wire['fiatValue'] = r.fiatValue;
    else if (r.usd !== undefined) wire['fiatValue'] = r.usd;
    if (r.currency !== undefined) wire['currency'] = r.currency;
    if (r.note !== undefined) wire['note'] = r.note;
    if (r.fee !== undefined) wire['reason'] = r.fee;
    return wire;
  });
}

/**
 * Guard: reject more than one recipient for single-recipient chains.
 *
 * WHAT: throws `ERR_MULTIPLE_RECIPIENTS` if `recipients.length > 1`.
 * WHY:  the ICP/KDA sugar takes a single `to`/`amount` (so this can't trip via
 *       the typed path), but this exported guard exists so any future array-based
 *       entry point enforces the same invariant locally — cheaper and clearer
 *       than a 60s round trip that returns the same platform error. Kept as a
 *       standalone export to match the "single source of truth for the rule"
 *       pattern the codebase favors over inline re-checks.
 */
export function assertSingleRecipient(
  recipients: readonly unknown[],
  method: 'pay' = 'pay',
): void {
  if (recipients.length > 1) {
    throw new NinjaError('ERR_MULTIPLE_RECIPIENTS', {
      method,
      hint: 'ICP and KDA payments allow exactly one recipient.',
    });
  }
}
