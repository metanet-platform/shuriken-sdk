/**
 * shuriken-sdk — misc utilities (`ninja.openLink`, `ninja.clipboard`).
 *
 * WHAT: `makeUtil` builds `{ openLink(url), clipboard: { write(text) } }` over
 *       the `open-link` and `write-clipboard` wire methods.
 * WHY:  these two don't fit a chain namespace but are core app affordances:
 *       `open-link` is a consent-gated, awaited round trip (the user approves the
 *       external navigation, so the caller wants to know when that resolves);
 *       `write-clipboard` is explicitly `noReply` in the manifest — the parent
 *       never sends a `write-clipboard-response` — so it MUST be fire-and-forget.
 *       Modeling their return types differently (`Promise<void>` vs `void`)
 *       encodes that asymmetry in the type system.
 */

import type { Codec } from '../protocol/codec';

/**
 * Build the `ninja` utility surface.
 *
 * WHAT: returns `{ openLink, clipboard }`.
 * WHY:  factored like the other command modules so index.ts assembles it from the
 *       one injected `codec`. The two members intentionally differ in shape to
 *       mirror their wire contracts (awaited consent vs one-way notify).
 */
export function makeUtil(codec: Codec): {
  openLink(url: string): Promise<void>;
  clipboard: { write(text: string): void };
} {
  return {
    /**
     * Open an external link behind the parent's consent overlay.
     *
     * WHAT: awaits the parent's `open-link-response`; resolves once the user has
     *       approved (or rejects `ERR_ABORTED` if they declined).
     * WHY:  this is a real round trip — the caller often wants to know whether the
     *       navigation was allowed, and the consent overlay makes it inherently
     *       async. We map the result to `void` (there's no useful payload) so the
     *       promise is purely a completion/rejection signal.
     */
    openLink(url: string): Promise<void> {
      return codec.call<void>('open-link', { url });
    },

    clipboard: {
      /**
       * Write text to the user's clipboard — fire-and-forget.
       *
       * WHAT: posts `write-clipboard` and returns immediately (`void`); there is
       *       NO response to await (manifest `noReply: true`).
       * WHY:  clipboard writes must be instantaneous and never block the caller on
       *       a reply that will never come. The codec's only send primitive is
       *       `call`, which arms a response timer, so we deliberately do NOT await
       *       it and we attach a no-op `.catch` to swallow the eventual
       *       `ERR_TIMEOUT` — otherwise a never-answered `noReply` command would
       *       surface as an unhandled promise rejection. From the caller's view
       *       this is a synchronous, one-way notification.
       *
       *       TODO(v1.0): add a dedicated `codec.notify(method, params)` that posts
       *       without registering a pending entry/timer, and route this through it
       *       so no phantom timeout is ever armed for `noReply` commands.
       */
      write(text: string): void {
        // Detach: no await, and neutralize the pending-timer rejection so a
        // command that never replies can't crash the host as an unhandled reject.
        void codec.call('write-clipboard', { text }).catch(() => {});
      },
    },
  };
}
