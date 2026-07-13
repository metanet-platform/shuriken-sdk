import { defineConfig } from 'tsup';

// Build config. Two entry points -> two subpath exports:
//   src/index.ts  -> "shuriken-sdk"        (framework-free core)
//   src/react.tsx -> "shuriken-sdk/react"  (React adapter; react is a peer dep)
//
// We ship BOTH ESM and CJS so the package drops into modern (Vite/ESM) and
// legacy (CRA/webpack/CJS) projects alike, with hand-written .d.ts for full
// autocomplete even from plain-JS consumers.
//
// `noExternal` inlines the crypto primitives at build time so the published
// package has ZERO runtime dependencies — an app that installs `shuriken-sdk`
// inherits no transitive supply-chain surface (see PROTOCOL.md > Security).
export default defineConfig({
  entry: {
    index: 'src/index.ts',
    react: 'src/react.tsx',
  },
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  treeshake: true,
  sourcemap: true,
  minify: false,
  splitting: false,
  outExtension({ format }) {
    return { js: format === 'cjs' ? '.cjs' : '.js' };
  },
  // `poseidon-lite` is inlined for the same zero-runtime-deps reason as @noble:
  // it backs the ZK proof verifier (src/zk/*) and must ship inside the bundle,
  // never as a `dependencies` entry the consuming app has to trust.
  noExternal: ['@noble/curves', '@noble/hashes', 'poseidon-lite'],
  external: ['react'],
  // Resolve dependencies with the BROWSER export condition. `@noble/hashes`
  // ships a conditional `./crypto` subpath: the `node` condition pulls in
  // `cryptoNode.js` (`import * as nc from 'node:crypto'`), which a browser
  // bundler (Vite) externalizes to a stub with no `webcrypto` export and then
  // fails to build the consuming app. The browser condition (`crypto.js`) uses
  // `globalThis.crypto` instead — universally available (browsers + Node ≥19) —
  // so the published bundle stays dependency-free AND browser-safe. This SDK
  // runs inside an iframe on metanet.page, so `browser` is the correct platform.
  platform: 'browser',
});
