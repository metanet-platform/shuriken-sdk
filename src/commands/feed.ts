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
 * WHY:  `previewAsset` may be a `File`/`Blob`; structured-clone carries the binary
 *       across `postMessage` intact (the transport posts the raw object, not JSON,
 *       so Blobs survive). The parent (mediaHandler.js line 24) reads the content
 *       off `data.detail.params` — a NESTED `params` object — so we wrap the
 *       caller's content under `{ params }` rather than spreading it flat into
 *       `detail`. Spreading it flat (the old behavior) left `detail.params`
 *       undefined and the overlay opened with an empty form.
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
      // Nest under `params` so the content lands at `detail.params`, which is
      // exactly where mediaHandler.js reads it (`...(data.detail.params || {})`).
      return codec.call<CreatePostResult>('create-post', { params });
    },
  };
}
