"use strict";

import type {
  SevenZipFileSummary,
  SevenZipFolderSummary,
  SevenZipParsedNextHeader
} from "../../analyzers/sevenz/index.js";

export const describeCoders = (
  coders: SevenZipFolderSummary["coders"] | undefined
): string => {
  if (!coders?.length) return "-";
  return coders
    .map(coder => {
      const parts = [];
      if (coder.archHint) parts.push(coder.archHint);
      const methodId =
        typeof coder.methodId === "string" && coder.methodId
          ? `id ${coder.methodId}`
          : null;
      if (methodId) parts.push(methodId);
      const suffix = parts.length ? ` (${parts.join(", ")})` : "";
      return `${coder.id}${suffix}`;
    })
    .join(" + ");
};

export const KNOWN_METHODS = [
  [
    "00",
    "COPY",
    "Stores data with no compression; useful for already-compressed inputs."
  ],
  [
    "03",
    "DELTA",
    "Simple byte-wise delta filter; often used before compression for audio (WAV) or similar data."
  ],
  [
    "04",
    "BCJ",
    "Generic branch converter; normalizes relative jumps in executable code to improve compression."
  ],
  [
    "030101",
    "LZMA",
    "Lempel-Ziv-Markov chain algorithm; 7-Zip's original high-ratio general-purpose compressor."
  ],
  [
    "03030103",
    "P7Z_BCJ",
    "x86 BCJ filter as used by 7-Zip; prepares 32-bit or 64-bit x86 code for better compression."
  ],
  [
    "0303011b",
    "P7Z_BCJ2",
    "BCJ2 variant used by 7-Zip; splits jump targets into separate streams for higher ratios on large executables."
  ],
  [
    "03030205",
    "BCJ_PPC",
    "PowerPC branch converter; improves compression of PowerPC executables."
  ],
  [
    "03030301",
    "BCJ_IA64",
    "IA-64 (Itanium) branch converter; improves compression of IA-64 executables."
  ],
  [
    "03030501",
    "BCJ_ARM",
    "ARM32 branch converter; improves compression of ARM executables."
  ],
  [
    "03030701",
    "BCJ_ARMT",
    "ARM-Thumb branch converter; improves compression of Thumb-mode ARM executables."
  ],
  [
    "03030805",
    "BCJ_SPARC",
    "SPARC branch converter; improves compression of SPARC executables."
  ],
  [
    "21",
    "LZMA2",
    "Improved LZMA with better multithreading and chunking; default method in many modern 7z archives."
  ],
  [
    "040202",
    "BZIP2",
    "Block-sorting (BWT) compressor; historically common, tends to be slower and slightly weaker than LZMA2."
  ],
  [
    "040108",
    "DEFLATE",
    "Classic ZIP-style compressor used for compatibility; usually gives lower ratios than LZMA2."
  ],
  [
    "040109",
    "DEFLATE64",
    "Extended Deflate variant with 64K window; mostly used for compatibility, often only for extraction."
  ],
  [
    "04f71101",
    "ZSTD",
    "Zstandard compressor; focuses on fast decompression with good ratios."
  ],
  [
    "04f71102",
    "BROTLI",
    "Brotli compressor; often used for web content, good density at moderate speeds."
  ],
  [
    "04f71104",
    "LZ4",
    "LZ4 compressor; very fast, lower ratios than LZMA2 or ZSTD."
  ],
  [
    "04f71105",
    "LZS",
    "LZS-family compressor; compatibility-oriented, not widely used in 7z archives."
  ],
  [
    "04f71106",
    "LIZARD",
    "Lizard compressor; member of the LZ4/ZSTD family with tuned trade-offs between speed and ratio."
  ],
  [
    "06f10701",
    "AES-256",
    "Content encryption using AES-256; combined with a compression method rather than replacing it."
  ]
];

export const describeHeaderKind = (
  parsed: SevenZipParsedNextHeader | undefined
): string => {
  if (!parsed) return "Unknown (next header not parsed)";
  if (parsed.kind === "header") {
    return "Plain Header structure: metadata is stored uncompressed at the next-header location.";
  }
  if (parsed.kind === "encoded") {
    return "Encoded Header: the header database itself is compressed or encrypted; this viewer does not decode it.";
  }
  if (parsed.kind === "empty") {
    return "Empty Header: no header database is present after the signature header.";
  }
  if (parsed.kind === "unknown") {
    const typeText =
      parsed.type != null ? `0x${parsed.type.toString(16)}` : "unknown id";
    return `Unexpected next-header type ${typeText}.`;
  }
  return String(parsed.kind);
};

export const describeFileType = (file: SevenZipFileSummary): string => {
  if (file.isAnti) return "Anti-item";
  if (file.isDirectory) return "Directory";
  if (file.isEmptyStream && file.isEmptyFile) return "Empty file";
  if (file.isEmptyStream) return "Metadata only";
  if (file.hasStream === false) return "No stream";
  return "File";
};

