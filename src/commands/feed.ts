/**
 * shuriken-sdk — `create-post` command sugar (`ninja.feed`).
 *
 * WHAT: `makeFeed` builds `{ createPost(params) }` over the `create-post` wire
 *       method.
 * WHY:  publishing to the Metanet feed is a consent-gated, wallet-backed action.
 *       The app NAME is forced platform-side from the registered app (so a
 *       malicious embed cannot spoof another app's identity on a post) — the SDK
 *       therefore deliberately does NOT accept or forward an app name, and passes
 *       only the caller-authored content through. Keeping this as a one-method
 *       namespace leaves room for `feed.*` to grow (edit/delete) without changing
 *       the call site shape.
 */

import type { Codec } from '../protocol/codec';
import type { CreatePostParams, CreatePostResult } from '../types';

/**
 * Build the `ninja.feed` sugar object.
 *
 * WHAT: returns `{ createPost }`, a typed wrapper over `codec.call('create-post', …)`.
 * WHY:  `previewAsset` may be a `File`/`Blob`; we forward the params object
 *       verbatim so structured-clone carries the binary across `postMessage`
 *       intact (the transport posts the raw object, not JSON, so Blobs survive).
 *       No local reshaping is needed — the manifest's request schema matches the
 *       `CreatePostParams` type field-for-field.
 */
export function makeFeed(codec: Codec): { createPost(params: CreatePostParams): Promise<CreatePostResult> } {
  return {
    /**
     * Publish a post to the user's Metanet feed.
     *
     * @param params headline (required) + optional NFT description, preview
     *               asset (File/Blob), and an embedded app descriptor.
     * @returns the new `postId`.
     */
    createPost(params: CreatePostParams): Promise<CreatePostResult> {
      return codec.call<CreatePostResult>('create-post', params);
    },
  };
}
