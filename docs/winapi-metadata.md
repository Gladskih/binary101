# WinAPI Metadata Assets

PE import enrichment is generated at build time from the official
[`Microsoft.Windows.SDK.Win32Metadata`](https://www.nuget.org/packages/Microsoft.Windows.SDK.Win32Metadata/)
NuGet package produced by the
[`microsoft/win32metadata`](https://github.com/microsoft/win32metadata)
project. The exact pinned version lives in `scripts/winapi-metadata/config.ts`.

The generator is TypeScript because the app already has a resilient PE/CLR
metadata parser for WinMD files. Reusing it keeps the pipeline dependency-free
and covered by the same malformed/truncated metadata rules as the browser
analyzer.

## Build Flow

1. `npm run generate:winapi-metadata` downloads the pinned NuGet package into
   `node_modules/.cache/binary101-winapi-metadata/`.
2. The generator extracts `Windows.Win32.winmd`, parses CLR metadata tables, and
   emits compact JSON assets under `public/winapi-metadata/`.
3. `npm run validate:winapi-metadata` validates the generated asset shape and
   cross-checks manifest/index/chunk counts.
4. `npm run build:with-winapi-metadata` regenerates, validates, and then runs the
   normal Vite build so GitHub Pages receives the assets in `dist/`.

## Asset Layout

Generated JSON files are build artifacts and are ignored by Git.

- `manifest.json` records source package name, source version, WinMD file name,
  format version, generation timestamp, DLL count, entry count, chunk list, and
  the entrypoint-index path.
- `entrypoint-index.json` maps exact export/entrypoint names to metadata module
  keys. It is used only as a fallback for API Set imports.
- one JSON chunk per metadata module/DLL records exact export names, namespace,
  readable signature, return/parameter types, calling convention, x86 stack-byte
  metadata where known, variadic marker, `SetLastError`, character-set marker,
  platform constraints, architecture constraints, and stable metadata IDs.

## Runtime Behavior

The site remains fully local in the browser. After PE imports are parsed, the
analyzer loads `manifest.json`, then only the chunks needed for modules present
in the eager and delay import tables. DLL identity is matched
case-insensitively; imported function names are exact matches, so `A` and `W`
exports are not mixed. Ordinal imports are left unenriched.

For `api-ms-win-*` API Set imports, the analyzer first tries the direct API Set
chunk. If the exact entrypoint is not present there, it loads
`entrypoint-index.json` and tries only host chunks that contain the same exact
entrypoint name.

## Guarantees And Limitations

- Win32Metadata only covers APIs present in the pinned package.
- API Set fallback is exact-name based. It improves common import-library
  contracts such as `api-ms-win-core-synch-l1-2-0.dll!Sleep`, but it does not
  parse a Windows runtime API Set schema.
- Pseudo import scopes without a module-style file extension are skipped because
  they are not useful PE import-library identities.
- Some metadata typedefs do not expose enough native-size information for exact
  x86 stack cleanup, so those parameters intentionally keep `x86StackBytes` as
  `null` instead of guessing.
