"use strict";

export {
  Attribute,
  AttributeTypeAndValue,
  Certificate,
  ContentInfo,
  EncapsulatedContentInfo,
  IssuerAndSerialNumber,
  RelativeDistinguishedNames,
  SignedAndUnsignedAttributes,
  SignedData,
  SignerInfo,
  Time
} from "pkijs";
// ### PKI.js TypeScript Workaround
// PE Authenticode verification uses `pkijs` at runtime, but importing `pkijs`
// directly from TypeScript currently breaks this repository's strict
// `npm run typecheck`.

// Before the workaround, `tsc` failed inside `node_modules/pkijs/build/index.d.ts`
// with errors like:

// ```text
// node_modules/pkijs/build/index.d.ts(5771,5): error TS2416:
// Property 'generateKey' in type 'AbstractCryptoEngine' is not assignable
// to the same property in base type 'ICryptoEngine'.

// Types of parameters 'algorithm' and 'algorithm' are incompatible.
// Type '"X25519" | { name: "X25519"; }' is not assignable to type '"Ed25519"'.
// ```

// The same failure repeated on lines `5771` through `5774`.

// To keep `tsc` strict without enabling `skipLibCheck`, the project imports
// PKI.js through a local adapter:

// - `analyzers/pe/pkijs-runtime.js` re-exports the real runtime objects from
//   `pkijs`.
// - `analyzers/pe/pkijs-runtime.d.ts` provides a small local type surface for the
//   subset of PKI.js APIs used by Binary101.

// This works because the rest of the project imports
// `./pkijs-runtime.js`, not `"pkijs"` directly. TypeScript therefore resolves
// types from the local sibling declaration file
// `analyzers/pe/pkijs-runtime.d.ts` instead of consuming the full upstream PKI.js
// declaration tree for those imports. At runtime nothing is mocked or replaced:
// the JS wrapper still loads the real `pkijs` package.

// As of `2026-04-11`, no exact upstream PKI.js issue was found for this specific
// `TS2416` / `generateKey` / `ICryptoEngine` mismatch in the repository issue
// search. The closest related results were:

// - [`#89 Add support for 25519 and 448`](https://github.com/PeculiarVentures/PKI.js/issues/89)
// - [`#406 Update dependencies and fix type annotation`](https://github.com/PeculiarVentures/PKI.js/pull/406)

// Searches checked at that date:

// - <https://github.com/PeculiarVentures/PKI.js/issues?q=generateKey+ICryptoEngine+TS2416>
// - <https://github.com/PeculiarVentures/PKI.js/issues?q=AbstractCryptoEngine+generateKey>
// - <https://github.com/PeculiarVentures/PKI.js/issues?q=ICryptoEngine>
// - <https://github.com/PeculiarVentures/PKI.js/issues?q=X25519+TypeScript>
