# PE Import Metadata Assets

Binary101 enriches PE imports with compact build-time metadata assets. The
browser still performs analysis locally; it lazy-loads only the metadata chunks
for DLLs that appear in the parsed eager or delay import tables.

## Sources

- WinAPI metadata comes from the pinned
  `Microsoft.Windows.SDK.Win32Metadata` NuGet package configured in
  `scripts/winapi-metadata/config.ts`.
- UCRT metadata comes from pinned `Microsoft.Windows.SDK.CPP` headers plus the
  pinned `Microsoft.Windows.SDK.CPP.x64` import library configured in
  `scripts/ucrt-metadata/config.ts`.

The UCRT generator uses `ucrt.lib` for the real export/module list, then parses
UCRT headers with MSVC-compatible `clang` JSON AST output. It keeps only function
declarations that match exported names. A small local `vcruntime*.h` shim is
used so CI does not need a Visual Studio include directory.

## Build Flow

1. `npm run generate:winapi-metadata` downloads Win32Metadata, extracts
   `Windows.Win32.winmd`, parses CLR metadata, and writes
   `public/winapi-metadata/*.json`.
2. `npm run generate:ucrt-metadata` downloads Windows SDK C++ packages, extracts
   UCRT headers and `ucrt.lib`, runs clang AST extraction, and writes
   `public/ucrt-metadata/*.json`.
3. `npm run validate:api-metadata` validates manifests and chunk counts.
4. `npm run prepare:windows-trust` validates
   `generated/windows-trust-store.generated.json`. On Windows it exports missing or invalid
   snapshots from LocalMachine Root, AuthRoot and Disallowed stores. A populated trusted-root
   list, a generation date, certificate DER data and no store-read warnings are required;
   an empty Disallowed list is valid. On Linux/macOS, supply a snapshot exported on Windows
   or extract the `windows-authenticode-trust` CI artifact to that path.
5. `npm run prepare:assets` prepares the certificate snapshot, regenerates both metadata
   families and validates their manifests, index and chunk counts. The existing NuGet cache
   avoids repeated package downloads. Generation still requires `clang`.

The ordinary `dev` and `build` commands run preparation automatically through
[npm lifecycle scripts](https://docs.npmjs.com/cli/v11/using-npm/scripts/#pre--post-scripts).
Both `build:with-api-metadata` and `build:with-winapi-metadata` are compatibility aliases
for this complete build. Build-time downloads do not change the browser's local analysis.

`preview` rebuilds before serving. Playwright starts it with a five-minute startup timeout
for asset preparation and refuses to reuse an existing server. Consequently, `test:e2e`
and direct Playwright runs test the current source and prepared assets. `npm test` runs unit
coverage followed by these browser tests. The CI browser job uses this same path, after
downloading the Windows-generated certificate artifact.

Vite resolves the browser's certificate snapshot to the ignored `generated/` file.
The checked-in empty snapshot is a fixture for isolated Node tests; it is never bundled by Vite.
Preparation reuses an already valid certificate snapshot. To refresh it explicitly on Windows, run
`powershell.exe -NoProfile -File scripts/dump-windows-authenticode-trust.ps1`.

## Asset Layout

Both metadata families emit a `manifest.json` plus per-DLL chunks. WinAPI also
emits `entrypoint-index.json` for exact-name API Set fallback.

- `public/winapi-metadata/manifest.json`
- `public/winapi-metadata/entrypoint-index.json`
- `public/winapi-metadata/<dll>.json`
- `public/ucrt-metadata/manifest.json`
- `public/ucrt-metadata/<dll>.json`

UCRT chunks include the `api-ms-win-crt-*` modules found in `ucrt.lib` plus an
aggregate `ucrtbase.dll` chunk for binaries that import UCRT directly.

## Matching Semantics

DLL/module names are matched case-insensitively. Function names are exact export
name matches, so decorated ANSI/Unicode or CRT variants are not merged.

WinAPI `api-ms-win-*` imports first try a direct chunk. If no direct exact match
exists, the WinAPI entrypoint index tries host DLL chunks containing the same
exact export name. UCRT `api-ms-win-crt-*` imports are routed to UCRT chunks and
are not sent through WinAPI API Set fallback.

## Guarantees And Limitations

- Generated JSON files are build artifacts and are ignored by Git.
- Metadata coverage is limited to the pinned packages.
- Parameter metadata includes `direction` when available or inferable:
  `in`, `out`, `inout`, or `null`. WinAPI direction comes from WinMD CLR
  `ParamAttributes`; UCRT direction is inferred conservatively from C types.
- Function metadata includes `noReturn`. UCRT records it from clang JSON AST
  attributes; WinAPI records it from WinMD `DoesNotReturnAttribute` metadata
  when the pinned package provides that attribute.
- UCRT extraction records function declarations only; exported variables and
  exports without a readable header declaration are intentionally omitted.
- UCRT architecture/platform constraints are not inferred per function. The
  manifest records that the export list came from the pinned x64 import library.
- x86 parameter stack-byte metadata is conservative. Unknown by-value structs
  keep parameter `x86StackBytes: null`; function cleanup is derived from calling
  convention at the use site instead of being stored in the assets.
