# Example gallery

The [Gallery samples workflow](../../.github/workflows/gallery-samples.yml) restores generated
examples from the GitHub Actions cache using a hash of the sample sources and build recipes.
On a cache miss, Windows builds the Hello World PE matrix selections, Inno Setup and Crinkler.
Ubuntu generates the remaining files, including AArch64 PE, NSIS, UPX and a two-slice Mach-O
object. The workflow caches the completed set and hands it to the site build as an artifact.

Vite includes the generated files as separate assets in the Pages build. Only the source and
build recipes are tracked in Git. The browser fetches a sample when selected and inspects its
bytes locally. The installers contain a sample text file. The JPEG has synthetic EXIF values,
and the RARJPG pairs that JPEG with a stored RAR5 archive containing the same text file.

- The [Inno Setup 6.4.3 compiler](https://github.com/jrsoftware/issrc/releases/tag/is-6_4_3)
  builds the installer for this non-commercial demo. See the vendor's
  [commercial licensing request](https://jrsoftware.org/inno-setup/documentation/topic_purchase.htm).
- [NSIS](https://nsis.sourceforge.io/License) builds the zlib-compressed installer.
- [UPX](https://github.com/upx/upx/blob/v5.1.0/LICENSE) compresses the original MSVC example.
- [LLVM](https://www.llvm.org/docs/CommandGuide/llvm-lipo.html) builds and combines ordinary
  Mach-O object files without Apple SDK headers or libraries.

To build the PE examples from the repository root on Windows, install Node 26, Visual Studio
with the C++ workload, Go and the .NET 10 SDK, then run:

```powershell
npm ci
.\scripts\build-gallery-pe.ps1
.\scripts\build-gallery-inno.ps1
```

The PE script selects five variants of the [PE matrix](../pe-disassembly/README.md), including
the managed assembly from the .NET publish directory and a NativeAOT build. Matrix logs are in
`generated/gallery-pe-matrix`. The workflow runs `scripts/build-gallery-crinkler.ps1` with Clang
and the x86 Windows SDK libraries to build the standard Crinkler example on a Windows runner.

On x86-64 Linux or WSL, install GCC, Go, Clang, LLD, `llvm-lipo`, 7-Zip, xorriso, UPX, NSIS,
FFmpeg with libvpx, libopus and libx264, and Python 3.11+ with ReportLab and Pillow 10+.
Run from the same checkout after building the Windows PE examples:

```sh
python3 scripts/build-gallery-linux.py
```

The scripts write to `generated/gallery/`. Run `npm run preview` from either environment to
build and serve the site. The gallery lists the samples available at build time and is hidden
when none are present. Generate the full set before running `tests/e2e/example-gallery.e2e.spec.ts`.
