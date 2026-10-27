# binary101

[![CI & Deploy][ci-badge]][ci-runs]
[![Unit coverage (lines)][coverage-badge]][coverage-report]

[binary101](https://gladskih.github.io/binary101/) is a browser-based binary file analyzer inspired by [regex101](https://regex101.com/), the Unix `file` utility, and VirusTotal. It began as a general-purpose format inspector and has grown especially deep support for executables. It presents structures, offsets and decoded values alongside explanations, statistics and previews. Files are processed locally, without uploads.

## Highlights

- **Instruction-set analysis.** Count instructions by x86/x86-64 and AArch64 ISA extension using control-flow-guided disassembly of PE and ELF files. Check what `-march` or a change in compiler flags actually produced, inspect SIMD usage, or compare the instruction mix of different builds and libraries.
- **Executable internals.** Explore PE and ELF layout, imports, exports, relocations, TLS, debug and unwind records, and code entry points. Deeper analysis covers DWARF, C++ RTTI, CLR/ReadyToRun, NativeAOT and Go runtime metadata, with demangling and WinAPI/UCRT import information where applicable.
- **Specialized PE files.** Recognize Windows Runtime metadata (WinMD), .NET reference assemblies, CLR native images, .NET apphosts, resource-only MUI images and EFI-stub Linux `bzImage` kernels.
- **Windows resources.** Decode more than icons and version strings: MSFT/SLTG type libraries, MUI configuration, compiled Windows Event manifests (WEVT), Ribbon BML, dialogs, manifests and managed .NET resources.
- **Authenticode verification.** Verify PE file digests and CMS signatures, inspect certificate chains and timestamps, and evaluate trust using a Windows CA snapshot exported in CI.
- **Images and media.** Read JPEG markers, EXIF/JFIF metadata and comments; PNG chunks and metadata; MP4 boxes and tracks; WebM/Matroska tags, attachments and codec details. For VP8 video, compare dimensions declared by the container with those found in keyframes. Preview images, audio and video in formats supported by the browser.
- **Embedded and unusual content.** Find RAR signatures inside JPEGs, scan PE overlays for embedded formats and archives, and extract validated archive payloads or PE files stored in resources. Recognize nested PE images in DOS stubs (including Intel TXT MLE), Valve integrity blocks, and UPX, Bun, NSIS and Inno Setup packaging.
- **Archives and other files.** Inspect entries, sizes and compression methods in ZIP/ZIP64, 7z, RAR and TAR. Extract stored/Deflate/LZMA ZIP entries and supported LZMA/LZMA2 7z entries, including solid folders. Other analyzers cover packet captures, PDF, SQLite, ISO 9660, Windows shortcuts and more.

## Formats

**Structured analysis:** PE/COFF, MZ, ELF, Mach-O; PNG, BMP, TGA, JPEG, GIF, WebP; WAV, AVI, ANI, ASF (WMV/WMA), WebM/Matroska, MP4/QuickTime/3GP, MPEG-PS, MP3, FLAC; PCAP, PCAP-NG, gzip, PDF, TAR, ISO 9660, ZIP, 7z, RAR 4/5, FB2, SQLite and LNK.

**Additional recognition:** TIFF, ICO/CUR, bzip2, XZ, LZ4, Zstandard, CAB, Ogg, AIFF, MIDI, FLV, MPEG-TS, WebAssembly, Java class, Android DEX, PDB, Office/OpenXML, EPUB, APK, VSIX and other container-based formats.

Analysis depth and available actions vary by format.

[ci-badge]: https://github.com/Gladskih/binary101/actions/workflows/ci.yml/badge.svg?branch=main&event=push
[ci-runs]: https://github.com/Gladskih/binary101/actions/workflows/ci.yml?query=branch%3Amain+event%3Apush
[coverage-badge]: https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fgladskih.github.io%2Fbinary101%2Fcoverage%2Fcoverage-summary.json&query=%24.total.lines.pct&label=unit%20coverage%20(lines)&suffix=%25&color=blue
[coverage-report]: https://gladskih.github.io/binary101/coverage/
