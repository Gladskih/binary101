# Binary101

Binary101 is a browser-based static web application for inspecting binary files. The app runs entirely in the browser using TypeScript/JavaScript (ES modules). Source is compiled to browser-ready JavaScript via a small TypeScript build step, but there is still no server-side code.

## Inspiration and Purpose
This project draws inspiration from tools like [regex101](https://regex101.com/), the Linux `file` utility, and VirusTotal. It is designed for educational and research purposes, helping users understand binary file structures and formats. By analyzing files locally in the browser, it ensures privacy and security, making it suitable for sensitive files.

## Features
- **Deep analyzers**: Detailed views for PE/COFF (PE32/PE32+), MS-DOS MZ, ELF 32/64, PNG, JPEG, GIF, WebP (RIFF), WAV (RIFF), AVI (RIFF), ANI (RIFF), WebM/Matroska, MP4/QuickTime/3GP (ISO-BMFF), MPEG Program Stream (MPEG-PS), PCAP capture files, gzip compressed data, PDF, TAR, ZIP (DOCX/XLSX/PPTX/OpenXML), 7z, RAR v4/v5, MP3, FB2, SQLite, LNK, ASF (WMV/WMA).
- **Detected/labelled**: Mach-O (32/64/FAT), text/HTML/XML/SVG/JSON/RTF/shebang, gzip/bzip2/XZ/LZ4/Zstandard, CAB, ISO-9660, OGG/AIFF/MIDI/AMR/AC3/DTS, FLV, MPEG PS/TS, RealMedia, Java class, Android DEX, WebAssembly, Windows Help (HLP), PDB, PCAP/PCAP-NG, DjVu, Microsoft Compound File (DOC/XLS/PPT/MSI/CHM), APK/VSIX/JAR/WAR/EAR/JMOD/EPUB/XPS labels, HEIF/HEIC.
- **Rendering**: previews for supported audio/video/image types.
- **Hashing**: SHA-256 and SHA-512 computed in-browser.
- **Privacy**: No uploads or network calls for analysis.

## Usage
- Drag and drop a file onto the page, paste a file, or use the file picker.
- View detailed analysis of the file structure and computed hashes.

## Project Structure (high level)
- `index.html` & `style.css` &mdash; page shell and styling (copied into `dist/` on build).
- `app.ts` &mdash; UI wiring: file selection, hashing, dispatch to analyzers and renderers (compiled to `dist/app.js`).
- `analyzers/` &mdash; TypeScript binary format detection and parsers. PE/COFF logic lives under `analyzers/pe/` and is split into small modules (headers, imports/exports, resources, TLS, CLR, relocations, etc.), compiled under `dist/analyzers/`.
- `renderers/` &mdash; TypeScript HTML renderers for parsed structures. The PE renderer lives under `renderers/pe/` and is split into headers, directory views, resources, and layout/sanity views, compiled under `dist/renderers/`.
- `binary-utils.ts`, `html-utils.ts` &mdash; shared helpers for hashing, byte/hex formatting and safe HTML generation.

## Contributing
Please see [CONTRIBUTING.md](CONTRIBUTING.md)

## License
This project is licensed under the MIT License. See `LICENSE` for details.
