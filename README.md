# Binary101

Binary101 is a browser-based static web application for inspecting binary files, with a focus on executable formats. The app runs entirely in the browser using modern JavaScript (ES modules) and does not require any server-side code or build steps.

## Inspiration and Purpose
This project draws inspiration from tools like [regex101](https://regex101.com/), the Linux `file` utility, and VirusTotal. It is designed for educational and research purposes, helping users understand binary file structures and formats. By analyzing files locally in the browser, it ensures privacy and security, making it suitable for sensitive files.

## Features
- **File Type Detection**: Automatically identifies binary file types.
- **PE/COFF Parsing**: Provides detailed insights into the structure of PE files.
- **Hashing**: Computes cryptographic hashes (e.g., SHA-256) for files.
- **Privacy-Focused**: All file analysis is performed locally in the browser.

## Getting Started

### Running the App
1. Clone the repository:
   ```bash
   git clone https://github.com/Gladskih/binary101.git
   ```
2. Navigate to the project directory:
   ```bash
   cd binary101
   ```
3. Start a local server:
   - Using Python:
     ```bash
     python -m http.server
     ```
   - Using Node.js:
     ```bash
     npx http-server .
     ```
   - Using VS Code:
     Install the "Live Server" extension and open `index.html`.
4. Open the app in your browser at `http://localhost:8080` (or the port specified by your server)

### Usage
- Drag and drop a binary file onto the app, or use the file input to upload.
- View detailed analysis of the file structure and computed hashes.

## Project Structure
- `index.html`: Main HTML file.
- `app.js`: Handles UI interactions and file processing.
- `analyzers/`: Contains format-specific parsers (e.g., `pe.js` for PE files).
- `pe-render.js`: Converts parsed PE data into HTML for display.
- `binary-utils.js`, `html-utils.js`, `hash.js`: Shared helpers for byte/hex formatting, HTML rendering, and hashing.

## Development
### Prerequisites
- Modern browser
- HTTP server

### Adding a New Analyzer
1. Create a new file in the `analyzers/` directory (e.g., `analyzers/elf.js`).
2. Implement `probe` and `parse` functions for the new format.
3. Update `analyzers/index.js` to include the new analyzer.

### Testing
- Use browser DevTools for debugging.
- Add unit tests for utility functions and parsers (e.g., with Jest or Mocha).
- Perform integration testing with tools like Puppeteer or Playwright.

## Contributing
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Submit a pull request with a clear description of your changes.

## License
You are free to use, modify, and distribute this project for any purpose, including commercial applications. The project must not be used for malicious purposes.
