export const exampleGroups = [
  ["Executables and objects", [
    ["hello-msvc-x64.exe", "PE · C / MSVC", "x86-64, static CRT, imports and unwind records"],
    ["hello-masm-x86.exe", "PE · x86 assembly", "32-bit entry point, Win32 imports, no CRT"],
    ["hello-go-x64.exe", "PE · Go", "x86-64, Go build information and function table"],
    ["HelloCSharp.dll", "PE · C#", "CLR metadata, assembly references and managed methods"],
    ["hello-nativeaot.exe", "PE · NativeAOT", "Native C# code and .NET runtime metadata"],
    ["hello-arm64.dll", "PE · AArch64", "Exported functions using CRC32 and AES instructions"],
    ["hello-gcc-x64.elf", "ELF · C / GCC", "x86-64 PIE, dynamic linking, relocations and DWARF"],
    ["hello-go-arm64.elf", "ELF · Go", "AArch64, static linking and Go runtime metadata"],
    ["hello-universal.o", "Mach-O · Universal", "x86-64 and AArch64 slices, symbols and relocations"],
    ["hello.wasm", "WebAssembly", "Host function import, exports, linear memory and data"]
  ]],
  ["Packers and installers", [
    ["hello-upx.exe", "UPX", "Compressed copy of the C / MSVC example, UPX headers and stub"],
    ["hello-crinkler.exe", "Crinkler", "32-bit demoscene executable, compression models and imports"],
    ["hello-inno.exe", "Inno Setup", "Setup data and the compressed installer engine"],
    ["hello-nsis.exe", "NSIS", "NSIS first header, installer flags and appended data"]
  ]],
  ["Archives and data", [
    ["hello-samples.zip", "ZIP", "Stored and Deflate entries, sizes and extraction"],
    ["hello-solid.7z", "7z · Solid", "Two files share a single LZMA2 stream"],
    ["hello-joliet.iso", "ISO 9660 · Joliet", "Volume descriptors, directory tree and file extraction"],
    ["hello.sqlite", "SQLite", "Database header, table, index and schema records"]
  ]],
  ["Images, video and PDF", [
    ["test-pattern.png", "PNG", "Lossless RGB image, chunk order and pixel dimensions"],
    ["test-pattern.jpg", "JPEG · EXIF", "Synthetic camera metadata, exposure and focal length"],
    ["test-pattern-rar.jpg", "JPEG + RAR", "A valid JPEG followed by a RAR5 archive with one text file"],
    ["test-pattern.gif", "GIF", "Animation frames, palette and loop metadata"],
    ["hello.pdf", "PDF", "Cross-reference table, trailer and document information"],
    ["test-pattern.webm", "WebM", "VP8 video, Opus audio, keyframes and track metadata"],
    ["test-pattern.mp4", "MP4", "H.264 video, AAC audio and MP4 box hierarchy"]
  ]]
] as const;
