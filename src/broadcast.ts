/**
 * shuriken-sdk — BSV broadcast client (the `pay.bsv({ broadcast: true })` finalizer).
 *
 * WHAT: takes the `rawTxHex` the parent returns from a `pay` request (a fully
 *       signed transaction that AUTHORIZES the UTXO spend but is NOT yet on the
 *       network) and finalizes it by POSTing to the Metanet overlay broadcast
 *       API. If you never call this, the UTXOs are authorized but unbroadcast.
 *
 * WHY:  the platform's `pay` overlay deliberately returns the raw tx so an app
 *       can inspect / chain / batch before committing. Broadcasting is a
 *       separate, app-authenticated HTTP step (not postMessage) against
 *       `https://api.metanet.ninja/data/api`.
 *
 * SIGNING — byte-exact with the live backend verifier
 * (metanet_back/src/middleware/auth.js). The request is authenticated with the
 * caller's delegated secp256k1 key (`genericUseSeed`, handed to the app in the
 * connection response). The backend computes:
 *
 *     canonical = JSON.stringify({ data })                 // data = {action, raws, params}
 *     msg       = Buffer.from( sha256(canonical).hex )     // ASCII BYTES of the 64-char hex digest
 *     verify( msg, x-signature )  against  x-pubkey
 *
 * `elliptic` (used by the backend) truncates `msg` to the leftmost 256 bits
 * before ECDSA — i.e. it operates on the FIRST 32 ASCII bytes of the hex
 * digest. We reproduce that exactly here with @noble so signatures verify,
 * without pulling in `elliptic` as a runtime dependency.
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';

/** The Metanet overlay broadcast endpoint. */
export const DEFAULT_BROADCAST_URL = 'https://api.metanet.ninja/data/api';

/** Per-transaction broadcast outcome returned by the API. */
export interface BroadcastTxResult {
  success: boolean;
  txid?: string;
  error?: string;
  [k: string]: unknown;
}

export interface BroadcastOptions {
  /** App identifier recorded with the broadcast (defaults to 'shuriken-sdk'). */
  source?: string;
  /** Override the endpoint (tests / staging). */
  apiUrl?: string;
  /** Override the timestamp (tests). Defaults to Date.now(). */
  timestamp?: number;
  /** Abort the HTTP request. */
  signal?: AbortSignal;
}

/**
 * Build the `x-pubkey` / `x-signature` headers for a canonical request body,
 * reproducing the backend's hash-of-hex-string + leftmost-256-bit truncation.
 *
 * @param canonical  the exact string that is also sent as the request body
 * @param privHex    64-char secp256k1 private key hex (the genericUseSeed)
 */
export function signBroadcastRequest(
  canonical: string,
  privHex: string,
): { pubkey: string; signature: string } {
  const priv = hexToBytes(normalizePrivHex(privHex));

  // sha256(canonical) -> 64-char hex digest, then the ASCII BYTES of that hex.
  const digestHex = bytesToHex(sha256(utf8ToBytes(canonical)));
  const asciiOfHex = utf8ToBytes(digestHex); // 64 bytes

  // elliptic truncates the message to the curve's bit length (256), keeping the
  // HIGH bits — for a 64-byte big-endian value that is exactly the first 32
  // bytes. @noble's ECDSA (with a 32-byte prehash) reduces mod n identically.
  const msgHash = asciiOfHex.slice(0, 32);

  // lowS: true == elliptic's { canonical: true }. DER hex == elliptic .toDER('hex').
  const sig = secp256k1.sign(msgHash, priv, { lowS: true });
  return {
    pubkey: bytesToHex(secp256k1.getPublicKey(priv, true)), // compressed (33 bytes)
    signature: sig.toDERHex(),
  };
}

/**
 * Broadcast one or more raw transactions. Resolves to a per-tx result array in
 * the same order as `raws`. Throws on transport/HTTP failure or a top-level
 * `{ success: false }` from the API.
 *
 * @param raws          raw tx hex strings (from the `pay` response's rawTxHex)
 * @param signingKeyHex the app's delegated secp256k1 key (genericUseSeed)
 */
export async function broadcastRawTxs(
  raws: string[],
  signingKeyHex: string,
  opts: BroadcastOptions = {},
): Promise<BroadcastTxResult[]> {
  if (!raws.length) return [];
  if (!signingKeyHex) {
    // No delegated key => we cannot authenticate the broadcast. Surface a clear
    // cause rather than a generic 401 from the server.
    throw new Error(
      'shuriken-sdk: broadcast requires a signing key (genericUseSeed). Connect first, ' +
        'or call pay.bsv(recipients, { broadcast: false }) to get the authorized rawTx without broadcasting.',
    );
  }

  // The canonical body MUST be byte-identical to what we sign; build it once.
  const data = {
    action: 'broadcastTransactions',
    raws,
    params: { source: opts.source ?? 'shuriken-sdk', timestamp: opts.timestamp ?? Date.now() },
  };
  const canonical = JSON.stringify({ data });
  const { pubkey, signature } = signBroadcastRequest(canonical, signingKeyHex);

  const res = await fetch(opts.apiUrl ?? DEFAULT_BROADCAST_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-pubkey': pubkey,
      'x-signature': signature,
    },
    body: canonical, // send the exact signed string
    signal: opts.signal,
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`shuriken-sdk: broadcast HTTP ${res.status} ${text}`.trim());
  }

  const result = (await res.json()) as { success?: boolean; error?: string; data?: BroadcastTxResult[] };
  if (!result.success) {
    throw new Error(`shuriken-sdk: broadcast rejected — ${result.error ?? 'unknown error'}`);
  }
  return result.data ?? [];
}

/** Broadcast a single raw tx and return just its result. */
export async function broadcastRawTx(
  rawTxHex: string,
  signingKeyHex: string,
  opts: BroadcastOptions = {},
): Promise<BroadcastTxResult> {
  const [first] = await broadcastRawTxs([rawTxHex], signingKeyHex, opts);
  if (!first) throw new Error('shuriken-sdk: broadcast returned no result');
  return first;
}

/** Strip an optional 0x prefix from a private key hex. */
function normalizePrivHex(hex: string): string {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]{64}$/.test(clean)) {
    throw new Error('shuriken-sdk: signing key must be a 64-char secp256k1 hex private key');
  }
  return clean;
}
