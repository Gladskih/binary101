"use strict";

import { dd, safe } from "../../html-utils.js";
import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import type {
  SevenZipArchiveFlags,
  SevenZipFileSummary,
  SevenZipFolderSummary,
  SevenZipParseResult,
  SevenZipParsedNextHeader,
  SevenZipStartHeader
} from "../../analyzers/sevenz/index.js";

const formatOffset = (value: number | bigint | null | undefined): string => {
  if (value == null) return "-";
  if (typeof value === "bigint") return `0x${value.toString(16)}`;
  return toHex32(value, 8);
};

const formatSize = (value: number | bigint | null | undefined): string => {
  if (value == null) return "-";
  if (typeof value === "bigint") {
    if (value <= BigInt(Number.MAX_SAFE_INTEGER)) {
      return formatHumanSize(Number(value));
    }
    return `${value.toString()} bytes`;
  }
  return formatHumanSize(value);
};

const toSafeNumber = (value: number | bigint | null | undefined): number | null => {
  if (typeof value === "number") return value;
  if (typeof value === "bigint" && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(value);
  }
  return null;
};

const formatSizeDetailed = (value: number | bigint | null | undefined): string => {
  if (value == null) return "-";
  const safeNumber = toSafeNumber(value);
  if (safeNumber != null) return formatHumanSize(safeNumber);
  const asBigInt = typeof value === "bigint" ? value : BigInt(Math.max(value, 0));
  return `${asBigInt.toString()} bytes`;
};

const describeCoders = (coders: SevenZipFolderSummary["coders"] | undefined): string => {
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

const ARCHIVE_FLAG_DEFS: Array<[number, string, string]> = [
  [1, "Solid", "Solid compression: multiple files share a single compressed stream."],
  [2, "Header enc", "Header is stored in encoded form (often encrypted or compressed)."],
  [4, "Encrypted data", "At least one folder appears to use AES-256 encryption."]
];

const FILE_FLAG_DEFS: Array<[number, string, string]> = [
  [1, "dir", "Directory entry; represents a folder rather than file data."],
  [2, "enc", "File data (or its folder) appears to be encrypted."],
  [4, "empty", "Zero-length file data after decompression."],
  [8, "no-stream", "Entry has no associated data stream (metadata only or anti-item)."]
];

const KNOWN_METHODS = [
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

const renderFlagsOrNone = (
  mask: number,
  defs: Array<[number, string, string?]>
): string => {
  const parts: string[] = [];
  if (!mask) {
    parts.push(
      `<span class="opt sel" title="No flags set">None</span>`
    );
  }
  defs.forEach(([bit, name, explanation]) => {
    const isSet = (mask & bit) !== 0;
    const label = explanation ? `${name} - ${explanation}` : name;
    const tooltip = `${label} (${toHex32(bit, 4)})`;
    parts.push(
      `<span class="opt ${isSet ? "sel" : "dim"}" title="${safe(tooltip)}">${name}</span>`
    );
  });
  return `<div class="optionsRow">${parts.join("")}</div>`;
};

const describeHeaderKind = (parsed: SevenZipParsedNextHeader | undefined): string => {
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

const formatRatio = (value: number | null | undefined): string => {
  if (value == null || !Number.isFinite(value)) return "-";
  return `${value.toFixed(1)}%`;
};

const renderOverview = (sevenZip: SevenZipParseResult, out: string[]): void => {
  const header = (sevenZip.startHeader || {}) as Partial<SevenZipStartHeader>;
  const next = (sevenZip.nextHeader || {}) as {
    crc?: number;
    parsed?: SevenZipParsedNextHeader;
  };
  const flags = sevenZip.structure?.archiveFlags as SevenZipArchiveFlags | undefined;
  const headerEncoding = sevenZip.headerEncoding || null;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">7z overview</h4>`);
  out.push(`<dl>`);
  const versionText =
    header.versionMajor != null && header.versionMinor != null
      ? `${header.versionMajor}.${header.versionMinor}`
      : "-";
  out.push(
    dd(
      "Version",
      versionText,
      "7z format version stored in the 32-byte signature header. Official releases currently use 0.4; older archives may report 0.3."
    )
  );
  out.push(
    dd(
      "Start header CRC",
      toHex32(header.startHeaderCrc ?? 0, 8),
      "CRC32 over the 20 bytes that follow this field in the signature header (Next Header offset, size and CRC). The Start Header CRC field itself is not included."
    )
  );
  const relativeOffset = header.nextHeaderOffset;
  const relativeText = relativeOffset != null ? formatOffset(relativeOffset) : "-";
  out.push(
    dd(
      "Next header offset",
      formatOffset(header.absoluteNextHeaderOffset),
      `File offset (absolute position in bytes) of the header database. Stored on disk as a UINT64 offset from the end of the 32-byte signature header; the stored relative offset here is ${relativeText}.`
    )
  );
  out.push(
    dd(
      "Next header size",
      formatSize(header.nextHeaderSize),
      "Size in bytes of the encoded header database. If the header is compressed or encrypted, this is the packed size, not the decoded size."
    )
  );
  out.push(
    dd(
      "Next header CRC",
      toHex32((next.crc ?? header.nextHeaderCrc) ?? 0, 8),
      "CRC32 checksum of the header database after decoding. A mismatch indicates damaged or tampered metadata."
    )
  );
  out.push(
    dd(
      "Header kind",
      safe(describeHeaderKind(next.parsed)),
      "Describes whether the next header is a plain Header structure, an encoded (compressed/encrypted) one, or missing/unknown."
    )
  );
  out.push(
    dd(
      "Archive flags",
      flags
        ? renderFlagsOrNone(
            (flags.isSolid ? 1 : 0) |
              (flags.isHeaderEncrypted ? 2 : 0) |
              (flags.hasEncryptedContent ? 4 : 0),
            ARCHIVE_FLAG_DEFS
          )
        : "-",
      "High-level properties derived from StreamsInfo: solid vs non-solid, whether the header is encoded/encrypted, and whether any file data appears encrypted."
    )
  );
  if (next.parsed?.kind === "encoded") {
    let encodingSummary = "Encoded header; details unavailable.";
    const folders = headerEncoding?.coders || [];
    if (folders.length) {
      const parts = folders.map(folder => {
        const chain = describeCoders(folder.coders);
        const encFlag = folder.isEncrypted ? "encrypted" : "not encrypted";
        return `Folder ${folder.index + 1}: ${chain || "(no coders)"} (${encFlag})`;
      });
      const headerEnc = headerEncoding?.hasEncryptedHeader;
      const note = headerEnc
        ? "header streams appear encrypted."
        : "header streams appear compressed but not encrypted.";
      encodingSummary = `${parts.join("; ")} – ${note}`;
    }
    out.push(
      dd(
        "Header encoding",
        safe(encodingSummary),
        "Shows how the header database itself is encoded (compression and/or encryption coders). Content is not decoded."
      )
    );
  } else {
    out.push(
      dd(
        "Header encoding",
        "Plain (not encoded)",
        "Header database is stored directly at the next-header location without an additional encoding layer."
      )
    );
  }
  out.push(`</dl>`);
  out.push(`</section>`);
};

const renderSignatureLayout = (sevenZip: SevenZipParseResult, out: string[]): void => {
  const header = sevenZip.startHeader as SevenZipStartHeader | undefined;
  if (!header) return;
  out.push(`<section>`);
  out.push(
    `<details><summary style="cursor:pointer;padding:.35rem .6rem;border:1px solid var(--border2);border-radius:8px;background:var(--chip-bg)"><b>Signature header map</b> (first 32 bytes)</summary>`
  );
  out.push(`<div style="margin-top:.5rem">`);
  out.push(
    `<div class="smallNote">The first 32 bytes of a 7z file are the signature header. It contains the magic signature, format version and the &quot;start header&quot; fields that locate the main header database.</div>`
  );
  out.push(
    `<table class="table"><thead><tr>` +
      `<th>Offset</th><th>Field</th><th>Value</th><th>Description</th>` +
    `</tr></thead><tbody>`
  );
  out.push(
    `<tr><td>0–5</td><td>Signature</td>` +
      `<td>37 7A BC AF 27 1C</td>` +
      `<td>6-byte magic &quot;7z\\xbc\\xaf'\\x1c&quot; that identifies the file as 7z.</td></tr>`
  );
  out.push(
    `<tr><td>6</td><td>VersionMajor</td>` +
      `<td>${header.versionMajor ?? "-"}</td>` +
      `<td>Major format version byte (currently 0).</td></tr>`
  );
  out.push(
    `<tr><td>7</td><td>VersionMinor</td>` +
      `<td>${header.versionMinor ?? "-"}</td>` +
      `<td>Minor format version byte (currently 4).</td></tr>`
  );
  out.push(
    `<tr><td>8–11</td><td>StartHeaderCRC</td>` +
      `<td>${toHex32(header.startHeaderCrc, 8)}</td>` +
      `<td>CRC32 over bytes 12–31 (NextHeaderOffset, NextHeaderSize, NextHeaderCRC).</td></tr>`
  );
  out.push(
    `<tr><td>12–19</td><td>NextHeaderOffset</td>` +
      `<td>${formatOffset(header.nextHeaderOffset)}</td>` +
      `<td>Relative offset (from byte 32) to the main header database.</td></tr>`
  );
  out.push(
    `<tr><td>20–27</td><td>NextHeaderSize</td>` +
      `<td>${formatSize(header.nextHeaderSize)}</td>` +
      `<td>Size in bytes of the encoded header database.</td></tr>`
  );
  out.push(
    `<tr><td>28–31</td><td>NextHeaderCRC</td>` +
      `<td>${toHex32(header.nextHeaderCrc ?? header.startHeaderCrc, 8)}</td>` +
      `<td>CRC32 of the header database after decoding.</td></tr>`
  );
  out.push(`</tbody></table>`);
  out.push(`</div></details>`);
  out.push(`</section>`);
};

const describeFileType = (file: SevenZipFileSummary): string => {
  if (file.isAnti) return "Anti-item";
  if (file.isDirectory) return "Directory";
  if (file.isEmptyStream && file.isEmptyFile) return "Empty file";
  if (file.isEmptyStream) return "Metadata only";
  if (file.hasStream === false) return "No stream";
  return "File";
};

const renderFolders = (sevenZip: SevenZipParseResult, out: string[]): void => {
  const folders = sevenZip.structure?.folders || [];
  if (!folders.length) return;
  out.push(`<section>`);
  out.push(
    `<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Compression folders (${folders.length})</h4>`
  );
  out.push(
    `<div class="smallNote">Each folder is a pipeline of coders (compression and filters) that turns packed bytes in the archive into one or more uncompressed streams. Solid archives group multiple files into a single folder.</div>`
  );
  out.push(
    `<table class="table"><thead><tr>` +
      `<th title="Folder index in the StreamsInfo.UnpackInfo list.">#</th>` +
      `<th title="Coder chain (compression and filters) applied to this folder, in order.">Coders</th>` +
      `<th title="Total uncompressed size of all streams produced by this folder.">Unpacked size</th>` +
      `<th title="Total size of the packed streams in the archive that feed this folder.">Packed size</th>` +
      `<th title="Whether any coder in this folder indicates AES-256 encryption.">Encrypted?</th>` +
    `</tr></thead><tbody>`
  );
  folders.forEach((folder, index) => {
    const coderText = describeCoders(folder.coders);
    const coders = safe(coderText);
    const unpacked = formatSizeDetailed(folder.unpackSize);
    const packed = formatSizeDetailed(folder.packedSize);
    const encrypted = folder.isEncrypted ? "Yes" : "No";
    out.push(
      `<tr><td>${index + 1}</td><td>${coders}</td>` +
        `<td>${unpacked}</td><td>${packed}</td><td>${encrypted}</td></tr>`
    );
  });
  out.push(`</tbody></table>`);
  out.push(`</section>`);
};

const renderFiles = (sevenZip: SevenZipParseResult, out: string[]): void => {
  const files = sevenZip.structure?.files || [];
  const folders = sevenZip.structure?.folders || [];
  if (!files.length) return;
  const limit = 200;
  const shown = files.slice(0, limit);
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Files (${files.length})</h4>`);
  out.push(
    `<div class="smallNote">Entries come from the FilesInfo header. For solid archives, several files can share one compressed folder, so only the first file in a folder may show a packed size and meaningful compression ratio.</div>`
  );
  out.push(
    `<table class="table"><thead><tr>` +
      `<th title="File index as stored in the FilesInfo section.">#</th>` +
      `<th title="File or directory name decoded from the UTF-16 name table.">Name</th>` +
      `<th title="How this entry is treated by the archive: regular file, directory, empty file, anti-item, metadata-only, or no-stream.">Type</th>` +
      `<th title="Logical size of the file after decoding (uncompressed size). May be 0 for empty files or directories.">Uncompressed</th>` +
      `<th title="Approximate compressed size accounted to this file. In solid archives, only the first file in a folder may reliably show a packed size.">Packed</th>` +
      `<th title="Packed size divided by uncompressed size. Values above 100% mean compression made the data larger.">Ratio</th>` +
      `<th title="Folder index and coder chain that carry this file&apos;s stream.">Method</th>` +
      `<th title="CRC32 of the uncompressed file data, if present in the header.">CRC</th>` +
      `<th title="Last modification time stored in the header (Windows FILETIME converted to UTC).">Modified</th>` +
      `<th title="File attribute mask from the header, usually matching Windows FILE_ATTRIBUTE_* flags.">Attributes</th>` +
      `<th title="Convenience flags derived from header fields: dir (directory), enc (encrypted), empty (zero-length), no-stream (no associated data).">Flags</th>` +
    `</tr></thead><tbody>`
  );
  shown.forEach((file: SevenZipFileSummary) => {
    const type = describeFileType(file);
    const modified = file.modifiedTime ? safe(file.modifiedTime) : "-";
    const attrs = file.attributes ? safe(file.attributes) : "-";
    const folder =
      file.folderIndex != null && file.folderIndex >= 0 ? folders[file.folderIndex] : null;
    let methodText = "-";
    if (folder) {
      const coderText = describeCoders(folder.coders);
      const folderLabel = `Folder ${folder.index + 1}`;
      methodText = coderText !== "-" ? `${folderLabel}: ${coderText}` : folderLabel;
    }
    const unpacked = formatSizeDetailed(file.uncompressedSize);
    const packed = formatSizeDetailed(file.packedSize);
    const ratio = formatRatio(file.compressionRatio);
    const crc = file.crc32 != null ? toHex32(file.crc32, 8) : "-";
    const flagMask =
      (file.isDirectory ? 1 : 0) |
      (file.isEncrypted ? 2 : 0) |
      (file.isEmpty ? 4 : 0) |
      (file.hasStream === false ? 8 : 0);
    const flagText = renderFlagsOrNone(flagMask, FILE_FLAG_DEFS);
    out.push(
      `<tr><td>${file.index}</td><td>${safe(file.name)}</td>` +
        `<td>${safe(type)}</td><td>${unpacked}</td><td>${packed}</td>` +
        `<td>${ratio}</td><td>${safe(methodText)}</td><td>${crc}</td>` +
        `<td>${modified}</td><td>${attrs}</td><td>${flagText}</td></tr>`
    );
  });
  out.push(`</tbody></table>`);
  if (files.length > limit) {
    const remaining = files.length - limit;
    out.push(`<div class="smallNote">${remaining} more entries not shown.</div>`);
  }
  out.push(`</section>`);
};

const renderKnownMethods = (out: string[]): void => {
  if (!KNOWN_METHODS.length) return;
  out.push(`<section>`);
  out.push(
    `<details><summary style="cursor:pointer;padding:.35rem .6rem;border:1px solid var(--border2);border-radius:8px;background:var(--chip-bg)"><b>Known 7z methods</b> (click to expand)</summary>`
  );
  out.push(`<div style="margin-top:.5rem">`);
  out.push(
    `<div class="smallNote">Methods recognized by this viewer (based on common 7-Zip method ids). Archives may also use custom methods with other ids; those are shown by their raw method id.</div>`
  );
  out.push(`<ul class="smallNote">`);
  KNOWN_METHODS.forEach(([id, name, description]) => {
    const label = safe(name);
    const idText = safe(id);
    const desc = description ? ` - ${safe(description)}` : "";
    out.push(`<li>${label} (id ${idText})${desc}</li>`);
  });
  out.push(`</ul>`);
  out.push(`</div></details>`);
  out.push(`</section>`);
};

const renderIssues = (sevenZip: SevenZipParseResult, out: string[]): void => {
  const issues = sevenZip.issues || [];
  if (!issues.length) return;
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">Notices</h4>`);
  out.push(`<ul>`);
  issues.forEach(issue => out.push(`<li>${safe(issue)}</li>`));
  out.push(`</ul>`);
  out.push(`</section>`);
};

export function renderSevenZip(sevenZip: SevenZipParseResult | null): string {
  if (!sevenZip || !sevenZip.is7z) return "";
  const out: string[] = [];
  renderOverview(sevenZip, out);
  renderFolders(sevenZip, out);
  renderFiles(sevenZip, out);
  renderKnownMethods(out);
  renderSignatureLayout(sevenZip, out);
  renderIssues(sevenZip, out);
  return out.join("");
}
