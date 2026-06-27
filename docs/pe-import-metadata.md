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
UCRT headers with MSVC-compatible `clang` AST output. It keeps only function
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
4. `npm run build:with-api-metadata` regenerates, validates, then runs the Vite
   build so static assets are copied into `dist/`.

GitHub Actions uses `build:with-api-metadata`, so Pages receives both WinAPI and
UCRT metadata assets.

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
- UCRT extraction records function declarations only; exported variables and
  exports without a readable header declaration are intentionally omitted.
- UCRT architecture/platform constraints are not inferred per function. The
  manifest records that the export list came from the pinned x64 import library.
- x86 parameter stack-byte metadata is conservative. Unknown by-value structs
  keep parameter `x86StackBytes: null`; function cleanup is derived from calling
  convention at the use site instead of being stored in the assets.
