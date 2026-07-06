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
 * Read a `File`/`Blob` as a base64 `data:` URL, dependency-free.
 *
 * WHY: the CreatePost overlay renders the in-post attachment from a data-URL
 *      string (`previewAsset.preview`, sourced from `previewAsset.data` — see
 *      CreatePost.js line 94/619). A raw `File`/`Blob` survives structured-clone
 *      but has neither `.data` nor `.preview`, so the overlay showed no image.
 *      We convert to a data-URL here (browser `FileReader`, no deps) so the
 *      overlay can render immediately, while ALSO keeping the original Blob under
 *      `.file` for the overlay's IPFS upload path (`item.file`, CreatePost.js
 *      line 223).
 */
function readAsDataURL(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () =>
      reject(reader.error ?? new Error('previewAsset could not be read'));
    reader.onload = () => resolve(reader.result as string);
    reader.readAsDataURL(blob);
  });
}

/**
 * Derive a file extension from a MIME type (e.g. `image/png` -> `png`).
 *
 * WHY: the overlay carries `extension`/`mimetype` onto the post's `preview_media`
 *      descriptor (CreatePost.js line 183). We don't have a filename for a bare
 *      `Blob`, so fall back to the MIME subtype; a `File` keeps its real
 *      extension when it has one.
 */
function extensionOf(asset: File | Blob): string | undefined {
  const name = (asset as File).name;
  if (typeof name === 'string' && name.includes('.')) {
    return name.slice(name.lastIndexOf('.') + 1).toLowerCase() || undefined;
  }
  const subtype = asset.type ? asset.type.split('/')[1] : '';
  return subtype ? subtype.toLowerCase() : undefined;
}

/**
 * Translate the ergonomic `previewAsset` (a `File`/`Blob`) into the EXACT object
 * shape the CreatePost overlay reads.
 *
 * The overlay (CreatePost.js line 93-98) initializes its preview from:
 *   - `previewAsset.data` — a data-URL string it copies to `.preview` and renders
 *     (line 619), and
 *   - `previewAsset.file` — the raw Blob it uploads to IPFS (line 223),
 * plus `type`/`mimetype`/`extension` for the post's `preview_media` descriptor
 * (line 183). So we hand it `{ type, file, data, mimetype, extension }`.
 */
async function toOverlayPreviewAsset(asset: File | Blob): Promise<{
  type: 'image';
  file: File | Blob;
  data: string;
  mimetype?: string;
  extension?: string;
}> {
  const data = await readAsDataURL(asset);
  return {
    type: 'image',
    file: asset,
    data,
    ...(asset.type ? { mimetype: asset.type } : {}),
    ...(extensionOf(asset) ? { extension: extensionOf(asset) } : {}),
  };
}

/**
 * Build the `ninja.feed` sugar object.
 *
 * WHAT: returns `{ createPost }`, a typed wrapper over `codec.call('create-post', …)`.
 * WHY:  the parent (mediaHandler.js line 24) reads the content off
 *       `data.detail.params` — a NESTED `params` object — so we wrap the caller's
 *       content under `{ params }` rather than spreading it flat into `detail`.
 *       Spreading it flat (the old behavior) left `detail.params` undefined and
 *       the overlay opened with an empty form. The public `previewAsset` stays an
 *       ergonomic `File`/`Blob`; we translate it into the overlay's structured
 *       `{ type, file, data, … }` shape here (see `toOverlayPreviewAsset`) so the
 *       overlay can both RENDER the preview (data-URL) and UPLOAD it (raw Blob).
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
    async createPost(params: CreatePostParams): Promise<CreatePostResult> {
      const { previewAsset, ...rest } = params;
      // Convert the ergonomic File/Blob to the overlay's structured preview shape.
      // Everything else (headline, nftDescription, appEmbed) passes through as-is.
      const wireParams = previewAsset
        ? { ...rest, previewAsset: await toOverlayPreviewAsset(previewAsset) }
        : rest;
      // Nest under `params` so the content lands at `detail.params`, which is
      // exactly where mediaHandler.js reads it (`...(data.detail.params || {})`).
      return codec.call<CreatePostResult>('create-post', { params: wireParams });
    },
  };
}
