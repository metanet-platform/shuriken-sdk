/**
 * shuriken-sdk — React bindings (published as the "shuriken-sdk/react" subpath).
 *
 * WHAT: a `<NinjaProvider>` that owns the single `Ninja` client's lifecycle, plus
 *       a family of hooks (`useNinja`, `useConnection`, `usePayment`,
 *       `useGeolocation`, `useQrScanner`) that expose that client and the common
 *       streaming/consent flows as idiomatic React state.
 * WHY:  every hand-copied app re-implemented "connect once, share the client,
 *       track connecting/connected/error, clean up the QR/geo stream on unmount"
 *       slightly differently — and most leaked the camera or geolocation watcher
 *       because they never sent the paired `-stop` on unmount. Centralizing that
 *       here means an app writes `const { pay } = usePayment()` and gets correct
 *       lifecycle, SSR-safety, and teardown for free.
 *
 * DESIGN NOTES
 *   - `react` is a PEER dependency (optional): this file is the only module that
 *     imports it, so a non-React consumer never pulls React in. We import the
 *     hooks by name from 'react'.
 *   - SSR-safety: `connect()` touches `window.parent`, which does not exist during
 *     server rendering. The provider therefore does nothing on the server and only
 *     kicks off the connection inside `useEffect` (which never runs on the server),
 *     leaving `status: 'idle'` in the server-rendered tree — a stable, hydration-safe
 *     initial state.
 *   - One client, one context: the provider builds exactly one `Ninja` and tears it
 *     down (`disconnect()`) on unmount, so pending calls reject with ERR_DISCONNECTED
 *     and the transport window listener is removed. No orphaned clients.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';

// The public entry: `connect()` builds the whole client, and the shared type
// contract flows through here so the React layer never redefines a type.
import { connect } from './index';
import { NinjaError, isNinjaError } from './errors';
import type {
  ChainKind,
  ConnectOptions,
  ConnectParams,
  ConnectResult,
  GeoFix,
  Ninja,
  ProofPurpose,
  QrScanResult,
  Subscription,
} from './index';

/* ------------------------------------------------------------------ *
 * Connection status — a small, exhaustive state machine.
 * ------------------------------------------------------------------ */

/**
 * The lifecycle of the provider's connection, as a closed union so consumers can
 * `switch` on it exhaustively:
 *  - `idle`       — before the connect effect runs (and the whole server render).
 *  - `connecting` — `connect()` (and optionally the identity handshake) in flight.
 *  - `connected`  — a non-anonymous identity was established.
 *  - `authenticating` — an `authenticate` follow-up (your backend) is in flight.
 *                   Only reached when the provider is given an `authenticate` prop.
 *  - `authenticated` — your `authenticate` follow-up resolved; `session` is set.
 *                   This is the "fully ready" state for apps with their own backend.
 *  - `anonymous`  — the client is up but the user shared no identity (autoConnect
 *                   returned an anonymous result). Distinct from `connected` so an
 *                   app can prompt for sign-in without treating it as an error.
 *  - `error`      — bring-up failed (e.g. ERR_NOT_EMBEDDED, or the handshake threw).
 */
export type NinjaStatus =
  | 'idle'
  | 'connecting'
  | 'connected'
  | 'authenticating'
  | 'authenticated'
  | 'anonymous'
  | 'error';

/* ------------------------------------------------------------------ *
 * Context value — everything the provider publishes to descendants.
 * ------------------------------------------------------------------ */

/**
 * WHAT: the shape stored in {@link NinjaContext}. Bundles the live client, the
 *       connection status, the normalized identity (when we auto-connected), any
 *       fatal error, and a `reconnect()` that rebuilds the client from scratch.
 * WHY:  hooks read narrow slices of this (`useNinja` just wants the client;
 *       `useConnection` wants status/me/error/reconnect) — keeping it one object
 *       means a single context and a single provider re-render path.
 */
interface NinjaContextValue {
  /** The assembled client, or `null` until the connect effect resolves (and on SSR). */
  ninja: Ninja | null;
  /** Where the bring-up currently is. */
  status: NinjaStatus;
  /** The normalized identity from `autoConnect`, or `null` if we didn't auto-connect. */
  me: ConnectResult | null;
  /**
   * The app session your `authenticate` follow-up returned (or `null` if you did
   * not pass `authenticate`, or it hasn't resolved yet). Held in memory only —
   * never persisted — and typed via {@link useSession}. This is where an app keeps
   * whatever its own backend hands back (a JWT, a user row, a role set, …).
   */
  session: unknown;
  /** The fatal bring-up error, if `status === 'error'`. Always a NinjaError. */
  error: NinjaError | null;
  /** Tear down the current client and run the whole bring-up again. */
  reconnect: () => void;
}

/**
 * The React context carrying the singleton client + connection state.
 *
 * WHY a nullable default: a hook used OUTSIDE a `<NinjaProvider>` must fail loudly
 * rather than silently hand back a half-built client. The default is `null`, and
 * every hook that requires the provider asserts on it (see `useCtx`).
 */
const NinjaContext = createContext<NinjaContextValue | null>(null);

// A stable display name aids React DevTools when inspecting the tree.
NinjaContext.displayName = 'NinjaContext';

/**
 * Internal: read the context or throw a clear, actionable error.
 *
 * WHY: the alternative — returning `null` and letting the caller hit a
 * `Cannot read property 'ninja' of null` deep in their code — is exactly the kind
 * of opaque failure this SDK exists to eliminate. We name the missing provider.
 */
function useCtx(): NinjaContextValue {
  const ctx = useContext(NinjaContext);
  if (ctx === null) {
    throw new Error(
      'shuriken-sdk/react: hook used outside <NinjaProvider>. Wrap your app tree in <NinjaProvider>.',
    );
  }
  return ctx;
}

/* ------------------------------------------------------------------ *
 * <NinjaProvider>
 * ------------------------------------------------------------------ */

/**
 * Props for {@link NinjaProvider}. All optional except `children`.
 */
export interface NinjaProviderProps {
  children: ReactNode;
  /**
   * Chains whose identities to request during the auto-connect handshake (V1;
   * harmless on V0). Passed straight to `ninja.connect({ request })`.
   */
  request?: ChainKind[];
  /**
   * Proof purposes to mint during the auto-connect handshake, batched into the
   * same consent overlay as the connection. Passed to `ninja.connect({ proofs })`.
   */
  proofs?: ProofPurpose[];
  /**
   * Optional per-app re-keying salt, forwarded to `ninja.connect({ salt })`. The
   * parent validates it (`/^[A-Za-z0-9._-]{1,64}$/` → `invalid_salt`).
   */
  salt?: string;
  /**
   * Optional nav-background hint (css color/gradient), forwarded to
   * `ninja.connect({ navbg })`. The parent sanitizes it to a color/gradient.
   */
  navbg?: string;
  /**
   * When `true` (the default), the provider calls `ninja.connect({ request, proofs })`
   * immediately after the client is built, so children see a resolved identity via
   * `useConnection().me` without any extra code. Set `false` to build the client
   * but defer the identity handshake to a user gesture (call `ninja.connect(...)`
   * yourself, e.g. behind a "Sign in" button).
   */
  autoConnect?: boolean;
  /**
   * Options forwarded to `connect()` (allowedOrigins, dev, protocols, timeouts, …).
   * The provider never mutates these; a change to the object identity triggers a
   * full rebuild (see the connect effect's dependency).
   */
  options?: ConnectOptions;

  /* ---- gate mode: turn the provider into an out-of-the-box auth gate ---- */

  /**
   * Gate the app behind the connection. When `true`, the provider renders its own
   * loader/anonymous/error UI and only reveals `children` once the user is ready
   * (`connected`, or `authenticated` when an `authenticate` follow-up is given).
   * This is the one-prop way to build an auth-protected iframe app: a loader shows
   * out of the box until the parent returns the connection-response and (optionally)
   * your backend authenticates the user. Default `false` (children always render;
   * you drive the UI from `useConnection()`).
   */
  gate?: boolean;
  /**
   * What to show while the gate is loading (`connecting`/`authenticating`). A node,
   * or a function of the current status. Defaults to a minimal built-in spinner.
   */
  loader?: ReactNode | ((ctx: { status: NinjaStatus }) => ReactNode);
  /**
   * What to show (gate mode) when the user is `anonymous` — i.e. they must sign in.
   * A node, or a function receiving `reconnect` (call it after the user signs in on
   * the platform). Defaults to a minimal built-in prompt.
   */
  renderAnonymous?: ReactNode | ((ctx: { reconnect: () => void }) => ReactNode);
  /**
   * What to show (gate mode) on a fatal bring-up `error`. A node, or a function of
   * `{ error, reconnect }`. Defaults to a minimal built-in message + Retry button.
   */
  renderError?: ReactNode | ((ctx: { error: NinjaError | null; reconnect: () => void }) => ReactNode);

  /* ---- the one app-custom seam: authenticate against YOUR backend ---- */

  /**
   * Follow-up hook: after the parent returns a verified, non-anonymous identity,
   * authenticate that user against YOUR OWN backend and return your app session.
   *
   * This is the ONE thing an app fills in — everything else works out of the box.
   * You receive the normalized `me` (with `me.canonicalId`, `me.app.pub`, and, if
   * you requested them, `me.proofs`) and the live `ninja` client (to sign a server
   * challenge via `ninja.call`, etc.). Return whatever your backend hands back
   * (a JWT, a user object, roles…); it is stored in memory as `session` and read
   * via {@link useSession}. In gate mode the loader stays up until this resolves;
   * a throw moves the gate to `error`.
   *
   * Example:
   *   authenticate={async (me) => {
   *     const r = await fetch('/api/session', {
   *       method: 'POST',
   *       body: JSON.stringify({ canonicalId: me.canonicalId, proof: me.proofs?.app }),
   *     });
   *     if (!r.ok) throw new Error('backend rejected identity');
   *     return r.json(); // -> becomes `session`
   *   }}
   */
  authenticate?: (me: ConnectResult, ninja: Ninja) => Promise<unknown>;
  /** Called once a non-anonymous identity is established (before `authenticate`). */
  onConnected?: (me: ConnectResult) => void;
  /** Called once your `authenticate` follow-up resolves, with its result + identity. */
  onAuthenticated?: (session: unknown, me: ConnectResult) => void;
  /** Called on a fatal bring-up error (also reflected in `useConnection().error`). */
  onError?: (error: NinjaError) => void;
}

/* ------------------------------------------------------------------ *
 * Default gate UI — dependency-free, overridable via props.
 * ------------------------------------------------------------------ */

/** Resolve a `ReactNode | (ctx) => ReactNode` prop against a context object. */
function pickNode<C>(
  node: ReactNode | ((ctx: C) => ReactNode) | undefined,
  ctx: C,
): ReactNode | undefined {
  return typeof node === 'function' ? (node as (c: C) => ReactNode)(ctx) : node;
}

// Shared centered full-viewport container for the built-in gate screens. Inline
// styles (no Tailwind / CSS import) so the gate renders correctly in ANY app.
const gateBoxStyle = {
  position: 'fixed',
  inset: 0,
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
  justifyContent: 'center',
  gap: 16,
  padding: 24,
  textAlign: 'center',
  background: '#0b0d12',
  color: '#e7e8ec',
  fontFamily: 'system-ui, -apple-system, "Segoe UI", sans-serif',
} as const;

/**
 * Built-in loader (gate mode). An inline SVG spinner animated with SMIL, so it
 * needs neither CSS keyframes nor a stylesheet. Override via the `loader` prop.
 */
function DefaultLoader(): ReactNode {
  return (
    <div role="status" aria-live="polite" style={gateBoxStyle}>
      <svg width="42" height="42" viewBox="0 0 50 50" aria-hidden="true">
        <circle cx="25" cy="25" r="20" fill="none" stroke="#26304d" strokeWidth="5" />
        <path
          fill="none"
          stroke="#7c8cff"
          strokeWidth="5"
          strokeLinecap="round"
          d="M25 5 a20 20 0 0 1 20 20"
        >
          <animateTransform
            attributeName="transform"
            type="rotate"
            from="0 25 25"
            to="360 25 25"
            dur="0.8s"
            repeatCount="indefinite"
          />
        </path>
      </svg>
      <span style={{ fontSize: 14, opacity: 0.8 }}>Connecting to the Metanet social network…</span>
    </div>
  );
}

/** Built-in anonymous prompt (gate mode). Override via `renderAnonymous`. */
function DefaultAnonymous({ reconnect }: { reconnect: () => void }): ReactNode {
  return (
    <div style={gateBoxStyle}>
      <span style={{ fontSize: 15 }}>Sign in on the Metanet social network to continue.</span>
      <button type="button" onClick={reconnect} style={gateButtonStyle}>
        I&apos;ve signed in — retry
      </button>
    </div>
  );
}

/** Built-in error screen (gate mode). Override via `renderError`. */
function DefaultError({
  error,
  reconnect,
}: {
  error: NinjaError | null;
  reconnect: () => void;
}): ReactNode {
  return (
    <div style={gateBoxStyle}>
      <span style={{ fontSize: 15 }}>
        Couldn&apos;t connect to the Metanet social network
        {error?.code ? ` (${error.code})` : ''}.
      </span>
      <button type="button" onClick={reconnect} style={gateButtonStyle}>
        Retry
      </button>
    </div>
  );
}

const gateButtonStyle = {
  appearance: 'none',
  border: '1px solid #2e3a5c',
  background: '#1a2036',
  color: '#e7e8ec',
  borderRadius: 8,
  padding: '8px 16px',
  fontSize: 14,
  cursor: 'pointer',
} as const;

/**
 * `NinjaProvider` — owns the single `Ninja` client and publishes it via context.
 *
 * WHAT (lifecycle):
 *   1. On the server (or before the first effect) it renders children with
 *      `status: 'idle'` and `ninja: null` — no `window` is touched, so SSR and the
 *      first client render agree (hydration-safe).
 *   2. In a mount effect it calls `connect(options)`. If that throws (e.g.
 *      `ERR_NOT_EMBEDDED`), it moves to `status: 'error'` with the NinjaError.
 *   3. If `autoConnect` is on, it then calls `ninja.connect({ request, proofs })`
 *      and stores the normalized identity as `me`, moving to `connected` or
 *      `anonymous` depending on whether an identity was shared.
 *   4. On unmount (or a rebuild via `reconnect()`/changed deps) it `disconnect()`s
 *      the client so pending calls reject and the window listener is removed.
 *
 * WHY the `nonce` state: `reconnect()` must force a full teardown+rebuild even
 * though `options`/`request`/`proofs` are unchanged. Bumping a nonce that the
 * connect effect depends on is the idiomatic React way to re-run an effect on
 * demand without stashing the client in a ref and imperatively poking it.
 *
 * WHY the `cancelled` guard: `connect()` and the handshake are async; if the
 * component unmounts (or a newer effect run supersedes this one) mid-flight, we
 * must not `setState` on a dead instance nor leak the just-built client. The
 * cleanup flips `cancelled` and disconnects whatever we managed to build.
 */
export function NinjaProvider(props: NinjaProviderProps): ReactNode {
  const {
    children,
    request,
    proofs,
    salt,
    navbg,
    autoConnect = true,
    options,
    gate = false,
    loader,
    renderAnonymous,
    renderError,
    authenticate,
  } = props;

  // The live client (null until built / after teardown). Also mirrored into a ref
  // so `reconnect`'s cleanup and the unmount cleanup can reach the SAME instance
  // the effect built, even across the async gap.
  const [ninja, setNinja] = useState<Ninja | null>(null);
  const [status, setStatus] = useState<NinjaStatus>('idle');
  const [me, setMe] = useState<ConnectResult | null>(null);
  // The app-backend session from `authenticate` (in-memory only; never persisted).
  const [session, setSession] = useState<unknown>(null);
  const [error, setError] = useState<NinjaError | null>(null);

  // Latest prop callbacks, kept in refs so the async bring-up effect can call the
  // freshest version WITHOUT listing them as effect deps — otherwise an inlined
  // `authenticate={async () => …}` would re-run the whole connection every render.
  const authRef = useRef(authenticate);
  const onConnectedRef = useRef(props.onConnected);
  const onAuthenticatedRef = useRef(props.onAuthenticated);
  const onErrorRef = useRef(props.onError);
  authRef.current = authenticate;
  onConnectedRef.current = props.onConnected;
  onAuthenticatedRef.current = props.onAuthenticated;
  onErrorRef.current = props.onError;

  // Bumped by `reconnect()` to re-run the connect effect (see WHY above).
  const [nonce, setNonce] = useState(0);
  const reconnect = useCallback(() => {
    // Reset to a clean pre-connect state, then force the effect to run again.
    setError(null);
    setMe(null);
    setSession(null);
    setStatus('idle');
    setNonce((n) => n + 1);
  }, []);

  useEffect(() => {
    // SSR / non-browser guard: there is no parent window to talk to on the server,
    // and `connect()` would throw ERR_NOT_EMBEDDED. We simply do nothing, leaving
    // `status: 'idle'` — the effect body never runs during server rendering anyway,
    // but this keeps the intent explicit and covers non-DOM test environments.
    if (typeof window === 'undefined') return;

    // Tracks whether THIS effect run is still the current one. Set false by the
    // cleanup so no post-unmount / superseded state writes land, and so we know to
    // immediately dispose a client that finished building after cancellation.
    let cancelled = false;
    // Holds the client this run built, so cleanup can dispose it even if the
    // component unmounts before `setNinja` committed.
    let built: Ninja | null = null;

    setStatus('connecting');

    (async () => {
      try {
        // 1. Build the transport/handshake/codec client. This can throw a typed
        //    NinjaError synchronously-in-promise (e.g. ERR_NOT_EMBEDDED, or a
        //    misconfigured origin policy).
        const client = await connect(options);
        if (cancelled) {
          // We were torn down mid-build: don't publish; dispose to free the
          // window listener and reject any in-flight negotiation.
          client.disconnect();
          return;
        }
        built = client;
        setNinja(client);

        // 2. Optionally run the identity handshake and record the result. When
        //    `autoConnect` is off we stop at "client built" — status stays
        //    `connecting` only until we flip it below.
        if (autoConnect) {
          // Build ConnectParams from only the provided fields (never send an
          // explicit `undefined` onto the wire). salt/navbg are forwarded verbatim;
          // the parent validates them (invalid_salt / css-color sanitizer).
          const connectParams: ConnectParams = {};
          if (request !== undefined) connectParams.request = request;
          if (proofs !== undefined) connectParams.proofs = proofs;
          if (salt !== undefined) connectParams.salt = salt;
          if (navbg !== undefined) connectParams.navbg = navbg;

          // The identity handshake. The provider stores the FULL result in memory
          // (React state) — including me.canonicalId and, if requested, me.proofs.
          // Nothing is persisted to storage; secrets never leave the vault/client.
          const result = await client.connect(connectParams);
          if (cancelled) return;
          setMe(result);

          if (result.anonymous) {
            // First-class, non-error terminal state: client up, no identity shared.
            setStatus('anonymous');
            return;
          }

          // A verified identity. Announce it, then optionally hand off to the app's
          // own backend to establish an app session.
          onConnectedRef.current?.(result);
          setStatus('connected');

          // AUTHENTICATE (optional, app-custom): the ONE seam an app fills in. Keep
          // the gate loading (`authenticating`) until the backend responds; store
          // whatever it returns as `session` (read via useSession). A throw here is
          // surfaced as a bring-up error (gate → error) via the outer catch.
          const authFn = authRef.current;
          if (authFn) {
            setStatus('authenticating');
            const appSession = await authFn(result, client);
            if (cancelled) return;
            setSession(appSession);
            setStatus('authenticated');
            onAuthenticatedRef.current?.(appSession, result);
          }
        } else {
          // Client is ready; identity deferred to a user-driven `ninja.connect`.
          // We report `anonymous` (no identity yet) rather than `connected` so a
          // gate that checks `status === 'connected'` stays closed until sign-in.
          setStatus('anonymous');
        }
      } catch (err) {
        if (cancelled) return;
        // Normalize to a NinjaError so `useConnection().error` is always typed and
        // localizable via `t(error.code)`. A non-NinjaError (unexpected) is wrapped.
        const nerr = isNinjaError(err)
          ? err
          : new NinjaError('ERR_UNKNOWN', {
              method: 'connection',
              hint: 'shuriken-sdk bring-up failed unexpectedly.',
              cause: err,
            });
        setError(nerr);
        setStatus('error');
        onErrorRef.current?.(nerr);
      }
    })();

    // Cleanup: on unmount or before a re-run (reconnect / changed deps), stop
    // publishing and dispose whatever client this run produced. Disposing rejects
    // pending calls with ERR_DISCONNECTED and removes the transport listener.
    return () => {
      cancelled = true;
      if (built) built.disconnect();
      setNinja(null);
    };
    // `request`/`proofs` are arrays: a caller who inlines `request={['bsv']}` gets a
    // new array each render. We intentionally depend on them so an actually-changed
    // request re-handshakes; callers who want to avoid churn should memoize/hoist
    // the array (documented). `nonce` forces the manual `reconnect()` rebuild.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [options, autoConnect, request, proofs, salt, navbg, nonce]);

  // Memoize the context value so consumers only re-render when a field they read
  // actually changes (not on every provider render).
  const value = useMemo<NinjaContextValue>(
    () => ({ ninja, status, me, session, error, reconnect }),
    [ninja, status, me, session, error, reconnect],
  );

  // Gate rendering (opt-in via `gate`). When off, children always render and the
  // app drives its own UI from the hooks — the original, unchanged behavior.
  // When on, the provider shows a loader until the user is ready, an anonymous
  // prompt if they must sign in, and an error screen on failure — all overridable.
  // "Ready" is `authenticated` when an `authenticate` follow-up is supplied,
  // otherwise `connected`. Every branch is still wrapped in the Provider so the
  // built-in / custom gate screens may themselves use the hooks.
  let gated: ReactNode = children;
  if (gate) {
    const ready = authenticate ? status === 'authenticated' : status === 'connected';
    if (status === 'error') {
      gated = pickNode(renderError, { error, reconnect }) ?? (
        <DefaultError error={error} reconnect={reconnect} />
      );
    } else if (status === 'anonymous') {
      gated = pickNode(renderAnonymous, { reconnect }) ?? <DefaultAnonymous reconnect={reconnect} />;
    } else if (ready) {
      gated = children;
    } else {
      // idle | connecting | authenticating | connected-pre-authenticate
      gated = pickNode(loader, { status }) ?? <DefaultLoader />;
    }
  }

  return <NinjaContext.Provider value={value}>{gated}</NinjaContext.Provider>;
}

/* ------------------------------------------------------------------ *
 * useNinja — the raw client.
 * ------------------------------------------------------------------ */

/**
 * `useNinja()` — the live `Ninja` client, or `null` before it's built / on SSR.
 *
 * WHY nullable: the client is genuinely absent during the server render and the
 * first client render (before the connect effect resolves). Returning `null`
 * (rather than throwing) lets a component render a loading state; callers gate
 * imperative calls with `if (ninja) …`. Use {@link useConnection} for status.
 */
export function useNinja(): Ninja | null {
  return useCtx().ninja;
}

/* ------------------------------------------------------------------ *
 * useConnection — status + identity + reconnect.
 * ------------------------------------------------------------------ */

/**
 * `useConnection()` — the connection state machine and controls.
 *
 * WHAT: `{ me, status, error, reconnect }` — the normalized identity from the
 *       auto-connect handshake (or `null`), the current {@link NinjaStatus}, the
 *       fatal error (or `null`), and a `reconnect()` that rebuilds the client.
 * WHY:  this is the hook a shell renders around: show a spinner on `connecting`,
 *       a sign-in prompt on `anonymous`, the app on `connected`, and a retry
 *       button wired to `reconnect()` on `error`.
 */
export function useConnection(): {
  me: ConnectResult | null;
  status: NinjaStatus;
  error: NinjaError | null;
  reconnect: () => void;
} {
  const { me, status, error, reconnect } = useCtx();
  return { me, status, error, reconnect };
}

/* ------------------------------------------------------------------ *
 * useSession — identity + your app-backend session (gate/authenticate).
 * ------------------------------------------------------------------ */

/**
 * `useSession<T>()` — the authenticated view: the platform identity PLUS the app
 * session your `authenticate` follow-up returned.
 *
 * WHAT: `{ me, session, status, error, reconnect, ready }`. `me` is the normalized
 *       identity; `session` is whatever your `NinjaProvider authenticate` returned
 *       (typed via the generic `T`); `ready` is `true` once the user is fully
 *       usable (`authenticated` when you supplied `authenticate`, else `connected`).
 * WHY:  an auth-protected app wants one hook that answers "who is this user and do
 *       I have my own session for them yet?". Pair it with `<NinjaProvider gate>`:
 *       the provider shows the loader until `ready`, so inside your gated tree this
 *       hook's `me`/`session` are already populated.
 *
 * The identity is held in memory only (never persisted); `session` is whatever you
 * chose to return from `authenticate` — keep secrets out of it.
 */
export function useSession<T = unknown>(): {
  me: ConnectResult | null;
  session: T | null;
  status: NinjaStatus;
  error: NinjaError | null;
  ready: boolean;
  reconnect: () => void;
} {
  const { me, session, status, error, reconnect } = useCtx();
  const ready = status === 'authenticated' || status === 'connected';
  return { me, session: (session as T | null) ?? null, status, error, ready, reconnect };
}

/* ------------------------------------------------------------------ *
 * usePayment — the pay namespace + a pending/error flag.
 * ------------------------------------------------------------------ */

/**
 * `usePayment()` — the payment sugar plus in-flight + error tracking.
 *
 * WHAT: `{ pay, pending, error }`. `pay` mirrors `ninja.pay` (`pay.bsv/icp/kda`)
 *       but each call is wrapped so `pending` is `true` for the duration and any
 *       thrown NinjaError is captured into `error` (while still re-throwing so the
 *       caller's own `try/catch`/promise chain works as usual).
 * WHY:  a payment is a consent-gated, potentially minute-long round trip; UIs need
 *       to disable the "Pay" button and surface a localized failure. Doing that
 *       correctly (resetting `pending` in a `finally`, clearing stale errors on a
 *       new attempt) is exactly the boilerplate every app got subtly wrong.
 *
 * The `pay` object is stable across renders as long as the client is; each method
 * is wrapped once via `useMemo`. When the client is `null` (pre-connect/SSR),
 * calling a method rejects with `ERR_NOT_EMBEDDED` so the promise contract holds.
 */
export function usePayment(): {
  pay: Ninja['pay'];
  pending: boolean;
  error: NinjaError | null;
} {
  const ninja = useNinja();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<NinjaError | null>(null);

  // A ref-counted "in flight" gate: concurrent payments (e.g. two buttons) keep
  // `pending` true until the LAST one settles, rather than the first settle
  // flipping it off while another is still open.
  const inflight = useRef(0);

  // Wrap a single pay method so it tracks pending/error around the underlying call.
  // Generic over the method's own args/return so the typed sugar signatures pass
  // straight through untouched.
  const wrap = useCallback(
    <A extends unknown[], R>(fn: ((...a: A) => Promise<R>) | undefined) =>
      async (...args: A): Promise<R> => {
        // No client yet: honor the promise contract with a typed rejection rather
        // than a TypeError on `undefined(...)`.
        if (!fn) {
          throw new NinjaError('ERR_NOT_EMBEDDED', {
            method: 'pay',
            hint: 'No Ninja client yet — call inside <NinjaProvider> after it connects.',
          });
        }
        // New attempt: clear any stale error and enter the pending state.
        setError(null);
        inflight.current += 1;
        setPending(true);
        try {
          return await fn(...args);
        } catch (err) {
          // Capture typed failures for the UI; wrap anything unexpected so `error`
          // is always a NinjaError. Re-throw so the caller's control flow is intact.
          const nerr = isNinjaError(err)
            ? err
            : new NinjaError('ERR_UNKNOWN', { method: 'pay', cause: err });
          setError(nerr);
          throw nerr;
        } finally {
          inflight.current -= 1;
          // Only leave the pending state once every concurrent payment has settled.
          if (inflight.current <= 0) {
            inflight.current = 0;
            setPending(false);
          }
        }
      },
    [],
  );

  // Rebuild the wrapped namespace whenever the client changes (its identity is our
  // signal that the underlying methods changed). Each method keeps its exact type.
  const pay = useMemo<Ninja['pay']>(
    () => ({
      bsv: wrap(ninja?.pay.bsv.bind(ninja.pay)),
      icp: wrap(ninja?.pay.icp.bind(ninja.pay)),
      kda: wrap(ninja?.pay.kda.bind(ninja.pay)),
    }),
    [ninja, wrap],
  );

  return { pay, pending, error };
}

/* ------------------------------------------------------------------ *
 * useGeolocation — a managed geo.watch() stream.
 * ------------------------------------------------------------------ */

/**
 * `useGeolocation()` — start/stop a live location stream as React state.
 *
 * WHAT: `{ fix, watching, start, stop }`. `start()` opens `ninja.geo.watch()` and
 *       pushes every fix into `fix`; `stop()` breaks the stream (sending the paired
 *       `geolocation-stop` wire message). `watching` reflects whether a stream is
 *       open.
 * WHY:  a geolocation watch is a long-lived, consent-gated stream that MUST be
 *       stopped — leaving it open drains battery and keeps the permission active.
 *       This hook guarantees the stream is stopped on `stop()` AND on unmount, and
 *       that starting twice doesn't leak the first watcher.
 *
 * The active iterator is held in a ref (not state) because it's an imperative
 * handle we only ever need to `.stop()` — storing it in state would cause needless
 * re-renders on every internal change.
 */
export function useGeolocation(): {
  fix: GeoFix | null;
  watching: boolean;
  start: () => void;
  stop: () => void;
} {
  const ninja = useNinja();
  const [fix, setFix] = useState<GeoFix | null>(null);
  const [watching, setWatching] = useState(false);

  // The live iterable's stop handle. `null` when no stream is open.
  const streamRef = useRef<(AsyncIterable<GeoFix> & { stop(): void }) | null>(null);
  // Guards against a state write after unmount from the async for-await loop.
  const mounted = useRef(true);

  // Imperatively stop and forget the current stream (idempotent).
  const stop = useCallback(() => {
    if (streamRef.current) {
      streamRef.current.stop();
      streamRef.current = null;
    }
    // Only touch state if we're still mounted (stop is also called from cleanup).
    if (mounted.current) setWatching(false);
  }, []);

  const start = useCallback(() => {
    // No client, or already watching: no-op (starting twice would orphan the first
    // stream and leak the permission).
    if (!ninja || streamRef.current) return;

    const stream = ninja.geo.watch();
    streamRef.current = stream;
    setWatching(true);

    // Drain the async iterable, pushing each fix into state. When the stream ends
    // (final frame, or `stop()` breaks the `for await`), fall through to cleanup.
    (async () => {
      try {
        for await (const f of stream) {
          if (!mounted.current) break;
          setFix(f);
        }
      } catch {
        // A stream error (e.g. ERR_NOT_SUPPORTED surfacing on the iterator) simply
        // ends the watch; the app can re-`start()`. We swallow it here rather than
        // crash the render — callers who need the error can use `ninja.geo` directly.
      } finally {
        // Whether the stream ended naturally or was stopped, reflect "not watching"
        // and drop the handle if it's still ours.
        if (streamRef.current === stream) streamRef.current = null;
        if (mounted.current) setWatching(false);
      }
    })();
  }, [ninja]);

  // Lifecycle: ensure any open stream is stopped on unmount (battery + permission).
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      // Stop directly (not via the memoized `stop`, whose `setWatching` is a no-op
      // post-unmount anyway) so the wire `geolocation-stop` is guaranteed to fire.
      if (streamRef.current) {
        streamRef.current.stop();
        streamRef.current = null;
      }
    };
  }, []);

  return { fix, watching, start, stop };
}

/* ------------------------------------------------------------------ *
 * useQrScanner — a managed qr.scan() subscription.
 * ------------------------------------------------------------------ */

/**
 * `useQrScanner()` — open the camera QR scanner and receive results as state.
 *
 * WHAT: `{ last, scanning, start, stop }`. `start(onResult?)` opens
 *       `ninja.qr.scan(...)`, storing each result in `last` and (optionally)
 *       forwarding it to the caller's `onResult`. `stop()` ends the scan, sending
 *       the paired `qr-scan-stop`. `scanning` reflects whether the camera is open.
 * WHY:  the QR scanner holds the camera open until explicitly stopped — the single
 *       most common leak in the copied SDKs. This hook stops it on `stop()` and on
 *       unmount, and refuses to open a second scanner over an already-open one.
 *
 * The subscription handle lives in a ref for the same reason as the geo stream:
 * it's an imperative `.stop()` handle, not render-affecting data.
 */
export function useQrScanner(): {
  last: QrScanResult | null;
  scanning: boolean;
  start: (onResult?: (r: QrScanResult) => void) => void;
  stop: () => void;
} {
  const ninja = useNinja();
  const [last, setLast] = useState<QrScanResult | null>(null);
  const [scanning, setScanning] = useState(false);

  // The live subscription (has `.stop()` + `.active`). `null` when closed.
  const subRef = useRef<Subscription | null>(null);
  const mounted = useRef(true);

  const stop = useCallback(() => {
    if (subRef.current) {
      subRef.current.stop();
      subRef.current = null;
    }
    if (mounted.current) setScanning(false);
  }, []);

  const start = useCallback(
    (onResult?: (r: QrScanResult) => void) => {
      // No client, or a scan already open: no-op (don't stack two camera sessions).
      if (!ninja || subRef.current) return;

      const sub = ninja.qr.scan((r: QrScanResult) => {
        if (!mounted.current) return;
        setLast(r);
        // Forward to the caller's handler, isolating any throw so a bad callback
        // can't break the scanner's internal state.
        if (onResult) {
          try {
            onResult(r);
          } catch {
            /* isolate app-callback faults */
          }
        }
      });

      subRef.current = sub;
      setScanning(true);
    },
    [ninja],
  );

  // Lifecycle: stop the scanner (release the camera) on unmount.
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      if (subRef.current) {
        subRef.current.stop();
        subRef.current = null;
      }
    };
  }, []);

  return { last, scanning, start, stop };
}

/* ------------------------------------------------------------------ *
 * Re-exports for convenience.
 * ------------------------------------------------------------------ */

/**
 * Re-export the context itself so advanced consumers can build custom hooks or a
 * `useContext(NinjaContext)` read without importing from the internal path. The
 * value is `null` outside a provider — the built-in hooks guard this for you.
 */
export { NinjaContext };
