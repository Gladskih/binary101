# Example gallery

The [Gallery samples workflow](../../.github/workflows/gallery-samples.yml) restores generated
examples from the GitHub Actions cache using a hash of the sample sources and build recipes.
On a cache miss it builds the PE examples on Windows, then generates ELF, WebAssembly, ZIP,
SQLite, PNG, JPEG, GIF, PDF and WebM on Ubuntu. It caches the completed set and passes it to the
site build as a workflow artifact. The cache can be evicted and is rebuilt on the next miss.

Vite includes the generated files as separate assets in the Pages build. Only the source and
build recipes are tracked in Git. The browser fetches a sample when selected and inspects its
bytes locally. The build ships a copy of the Go SDK license alongside each Go example.

To build the PE examples from the repository root on Windows, install Node 26, Visual Studio
with the C++ workload, Go and the .NET 10 SDK, then run:

```powershell
npm ci
.\scripts\build-gallery-pe.ps1
```

The script selects four variants of the [PE matrix](../pe-disassembly/README.md), including the
managed assembly from the .NET publish directory. Build logs are in `generated/gallery-pe-matrix`.

On x86-64 Linux or WSL, install GCC, Go, Clang, LLD, FFmpeg with libvpx and libopus, and
Python 3.11+ with ReportLab. Run from the same checkout:

```sh
python3 scripts/build-gallery-linux.py
```

Both scripts write to `generated/gallery/`. Run `npm run preview` from either environment to
build and serve the site. The gallery lists the samples available at build time and is hidden
when none are present. Generate both sets before running `tests/e2e/example-gallery.e2e.spec.ts`.
