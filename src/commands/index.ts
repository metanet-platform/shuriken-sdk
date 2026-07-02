/**
 * shuriken-sdk — command factory barrel.
 *
 * WHAT: re-exports every typed-sugar factory (`make*`) from one module.
 * WHY:  `src/index.ts` assembles the public `Ninja` object by calling each of
 *       these factories with the shared `codec` (and, for connect, the session
 *       setter). Collecting them behind one barrel means index.ts imports from a
 *       single path and the set of command namespaces is discoverable in one
 *       place — add a command module, export it here, wire it in index.ts.
 */

export { makeConnect } from './connect';
export { makePay, assertSingleRecipient } from './pay';
export { makeFeed } from './feed';
export { makeTx } from './tx';
export { makeProof } from './proof';
export { makeGeo } from './geo';
export { makeQr } from './qr';
export { makeUtil } from './util';
export { makeIdentity } from './identity';
