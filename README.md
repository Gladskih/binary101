# Binary101

Binary101 is a browser-based static web application for inspecting binary files, with a focus on executable formats. The app runs entirely in the browser using modern JavaScript (ES modules) and does not require any server-side code or build steps.

## Inspiration and Purpose
This project draws inspiration from tools like [regex101](https://regex101.com/), the Linux `file` utility, and VirusTotal. It is designed for educational and research purposes, helping users understand binary file structures and formats. By analyzing files locally in the browser, it ensures privacy and security, making it suitable for sensitive files.

## Features
- **File Type Detection**: Automatically identifies binary file types.
- **PE/COFF Parsing**: Provides detailed insights into the structure of PE files.
- **Hashing**: Computes cryptographic hashes (e.g., SHA-256) for files.
- **Privacy-Focused**: All file analysis is performed locally in the browser.

## Usage
- Drag and drop a binary file onto the app, or use the file input to upload.
- View detailed analysis of the file structure and computed hashes.

## Project Structure (high level)
- `index.html` & `style.css` &mdash; page shell and styling.
- `app.js` &mdash; UI wiring: file selection, hashing, dispatch to analyzers and renderers.
- `analyzers/` &mdash; binary format detection and parsers. PE/COFF logic lives under `analyzers/pe/` and is split into small modules (headers, imports/exports, resources, TLS, CLR, relocations, etc.).
- `renderers/` &mdash; HTML renderers for parsed structures. The PE renderer lives under `renderers/pe/` and is split into headers, directory views, resources, and layout/sanity views.
- `hash.js`, `binary-utils.js`, `html-utils.js` &mdash; shared helpers for hashing, byte/hex formatting and safe HTML generation.

## Supported file types
- Parsed with detailed views: PE/COFF (PE32 and PE32+), ELF 32/64, PNG, JPEG, GIF, WebP, PDF, TAR, ZIP (including DOCX/XLSX/PPTX and related OpenXML), 7z, RAR (v4/v5 headers and entries), MP3, FictionBook FB2.
- Detected/labelled without deep parsing: Mach-O (32/64/FAT), text/HTML/XML/SVG/JSON/RTF/shebang scripts, gzip/bzip2/XZ/LZ4/Zstandard, CAB, ISO-9660 images, FLAC/OGG/WAV/AIFF/MIDI/AMR/AC3/DTS, MP4/MOV (ISO BMFF), FLV/AVI/ASF, MPEG PS/TS, RealMedia, Matroska, SQLite, Java class files, Android DEX bytecode, WebAssembly (WASM), Windows Help (HLP), Windows shortcut (LNK), PDB, PCAP/PCAP-NG, DjVu, Microsoft Compound File (DOC/XLS/PPT/MSI/CHM signatures), ZIP-derived APK/VSIX/JAR/WAR/EAR/JMOD/E-book EPUB/XPS/FB2 labels.

## Contributing
Please see [CONTRIBUTING.md](CONTRIBUTING.md)

## License
This project is licensed under the MIT License. See `LICENSE` for details.
