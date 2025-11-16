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
- `analyzers/` &mdash; binary format detection and parsers (PE/COFF split into small modules such as `pe-core.js`, `pe-imports.js`, `pe-resources*.js`, etc.).
- `pe-render-headers.js` &mdash; renders DOS/COFF/Optional headers and data directories.
- `pe-render-directories.js` &mdash; renders PE directories (Load Config, Debug, Import/Export, TLS, CLR, Security, IAT).
- `pe-render-resources.js` &mdash; renders resource summary and per-type entries with previews (icons, manifests, version info).
- `pe-render-layout.js` &mdash; renders layout-oriented views (relocations, exception/pdata, bound/delay imports, coverage, sanity).
- `hash.js`, `binary-utils.js`, `html-utils.js` &mdash; shared helpers for hashing, byte/hex formatting and safe HTML generation.

## Contributing
Please see [CONTRIBUTING.md](CONTRIBUTING.md)

## License
You are free to use, modify, and distribute this project for any purpose, including commercial applications. The project must not be used for malicious purposes.
