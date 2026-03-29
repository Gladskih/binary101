# Binary101

Binary101 is a browser-based static web application for inspecting binary files. The app runs entirely in the browser using TypeScript/JavaScript (ES modules) and is built with Vite into a static site. There is still no server-side code.

## Inspiration and Purpose
This project draws inspiration from tools like [regex101](https://regex101.com/), the Linux `file` utility, and VirusTotal. It is designed for educational and research purposes, helping users understand binary file structures and formats. By analyzing files locally in the browser, it ensures privacy and security, making it suitable for sensitive files.

## Features
- **Deep analyzers**: Detailed views for PE/COFF (PE32/PE32+), MS-DOS MZ,
  ELF 32/64, Mach-O (32/64/FAT), PNG, BMP, TGA, JPEG, GIF, WebP (RIFF),
  WAV (RIFF), AVI (RIFF), ANI (RIFF), ASF (WMV/WMA), WebM/Matroska,
  MP4/QuickTime/3GP (ISO-BMFF), MPEG Program Stream (MPEG-PS), PCAP, PCAP-NG, gzip, PDF, TAR, ISO-9660, ZIP
  (DOCX/XLSX/PPTX/OpenXML), 7z, RAR v4/v5, MP3, FLAC, FB2, SQLite, LNK.
- **PE limitations**: CodeView/PDB extraction is currently RSDS-only; `NB10`
  and other legacy `NBxx` CodeView records are not decoded yet. Missing
  `.pdata` formats include 32-bit MIPS, Windows CE ARM/PowerPC/SH3/SH4, and
  Itanium.
- **Instruction-set detection**: for ELF and PE on x86/x86-64, the app can
  analyze sampled reachable code and report the instruction-set extensions it
  uses.
- **Detected/labelled**: text/HTML/XML/SVG/JSON/RTF/shebang, TIFF, ICO/CUR,
  bzip2/XZ/LZ4/Zstandard, CAB, OGG/AIFF/MIDI/AMR/AC3/DTS, FLV, MPEG-TS,
  RealMedia, Java class, Android DEX, WebAssembly, Windows Help (HLP), PDB,
  DjVu, Microsoft Compound File (DOC/XLS/PPT/MSI/CHM), HEIF/HEIC,
  and ZIP-based labels for FB2, ODT/ODS/ODP, EPUB, DOCX/XLSX/PPTX/OpenXML,
  APK, VSIX, JAR/WAR/EAR/JMOD, and XPS.
- **Rendering**: previews for supported audio/video/image types.
- **Hashing**: SHA-256 and SHA-512 computed in-browser.
- **Privacy**: No uploads or network calls for analysis.

## Usage
- Drag and drop a file onto the page, paste a file, or use the file picker.
- View detailed analysis of the file structure and computed hashes.

## Development
- `npm run dev` &mdash; start the Vite dev server.
- `npm run build` &mdash; create the production build in `dist/`.
- `npm run preview` &mdash; serve the built site locally on `http://127.0.0.1:4173`.

## Project Structure (high level)
- `index.html` & `style.css` &mdash; Vite HTML entry and page styling.
- `app.ts` &mdash; UI wiring: file selection, hashing, dispatch to analyzers and renderers; Vite bundles it into `dist/assets/`.
- `analyzers/` &mdash; TypeScript binary format detection and parsers. PE/COFF logic
  lives under `analyzers/pe/` and is split into small modules (headers,
  imports/exports, resources, TLS, CLR, relocations, Authenticode, exception
  data, etc.); CodeView debug parsing is currently RSDS-only, and some
  `.pdata` variants are still not implemented.
- `renderers/` &mdash; TypeScript HTML renderers for parsed structures. The PE renderer lives under `renderers/pe/` and is split into headers, directory views, resources, and layout/sanity views.
- `binary-utils.ts`, `html-utils.ts` &mdash; shared helpers for hashing, byte/hex formatting and safe HTML generation.

## Contributing
Please see [CONTRIBUTING.md](CONTRIBUTING.md)

## License
This project is licensed under the MIT License. See `LICENSE` for details.
