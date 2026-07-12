"use strict";

import { hex, humanSize } from "../../binary-utils.js";
import { escapeHtml, renderOptionChips } from "../../html-utils.js";
import type { PeUpxPackerFinding } from "../../analyzers/pe/packers/index.js";

// UPX compression method identifiers are stable on-disk values.
// https://github.com/upx/upx/blob/devel/src/conf.h
const UPX_COMPRESSION_METHODS: Array<[number, string]> = [
  [2, "NRV2B LE32"],
  [3, "NRV2B 8-bit"],
  [4, "NRV2B LE16"],
  [5, "NRV2D LE32"],
  [6, "NRV2D 8-bit"],
  [7, "NRV2D LE16"],
  [8, "NRV2E LE32"],
  [9, "NRV2E 8-bit"],
  [10, "NRV2E LE16"],
  [14, "LZMA"]
];

// UPX PE format identifiers are defined alongside the other executable formats.
// https://github.com/upx/upx/blob/devel/src/conf.h
const UPX_PE_FORMATS: Array<[number, string, string]> = [
  [9, "9 PE32/i386", "Windows PE32 for Intel i386"],
  [21, "21 PE/CE ARM", "Windows CE PE for ARM"],
  [36, "36 PE32+/AMD64", "Windows PE32+ for AMD64"],
  [43, "43 PE32+/ARM64", "Windows PE32+ for ARM64"],
  [44, "44 PE32+/ARM64EC", "Windows PE32+ for ARM64EC"]
];

// Names follow the PE-relevant x86/ARM entries in UPX's filter registry and packers.
// https://github.com/upx/upx/blob/devel/src/filter/filter_impl.cpp
const UPX_FILTER_LABELS: Readonly<Record<number, string>> = {
  0x00: "No filter",
  0x11: "x86 E8 call transform",
  0x12: "x86 E9 jump transform",
  0x13: "x86 E8/E9 call/jump transform",
  0x14: "x86 E8 call transform (LE byte swap)",
  0x15: "x86 E9 jump transform (LE byte swap)",
  0x16: "x86 E8/E9 call/jump transform (LE byte swap)",
  0x24: "x86 E8 CTO transform (LE byte swap)",
  0x25: "x86 E9 CTO transform (LE byte swap)",
  0x26: "x86 E8/E9 CTO transform (LE byte swap)",
  0x36: "x86 E8/E9 CTO/JMP transform (LE byte swap)",
  0x46: "x86 E8/E9 CTO/JMP multi-block transform",
  0x49: "x86 E8/E9/Jcc CTO transform",
  0x50: "ARM 24-bit branch transform (LE)"
};

export const upxFilterLabel = (filter: number): string =>
  UPX_FILTER_LABELS[filter] ?? "Unknown UPX filter";

const formatUpxBytes = (size: number): string =>
  size < 1024 ? `${size} bytes` : humanSize(size);

const formatCompressionLevel = (level: number): string =>
  level === 10 ? "10 / 10 (--best)" : `${level} / 10 (-${level})`;

const formatFileRatio = (ratio: number): string =>
  ratio <= 100
    ? `${ratio.toFixed(1)}% (${(100 - ratio).toFixed(1)}% smaller)`
    : `${ratio.toFixed(1)}% (${(ratio - 100).toFixed(1)}% larger)`;

const renderUpxFormatChips = (format: number): string =>
  renderOptionChips(
    format,
    UPX_PE_FORMATS.some(([code]) => code === format)
      ? UPX_PE_FORMATS
      : [...UPX_PE_FORMATS, [format, `${format} Unknown format`, "Unknown UPX PE format"]]
  );

const renderUpxRow = (
  label: string,
  valueHtml: string,
  meaning: string,
  valueClass = ""
): string =>
  `<tr><th scope="row" class="peUpxTable__field">${escapeHtml(label)}</th>` +
  `<td${valueClass ? ` class="${valueClass}"` : ""}>${valueHtml}</td>` +
  `<td class="smallNote pePackerFinding__meaning">${escapeHtml(meaning)}</td></tr>`;

const renderSizeRows = (finding: PeUpxPackerFinding): string => {
  const header = finding.packHeader;
  const ratio = finding.packedFileSize / header.originalFileSize * 100;
  return renderUpxRow(
    "Packed block size",
    escapeHtml(formatUpxBytes(header.packedSize)),
    "Compressed payload bytes covered by the packed Adler-32.",
    "peNumeric"
  ) + renderUpxRow(
    "Unpacked block size",
    escapeHtml(formatUpxBytes(header.unpackedSize)),
    "Decompressed in-memory PE image block; virtual layout and UPX reconstruction " +
      "data are included.",
    "peNumeric"
  ) + renderUpxRow(
    "Packed file size",
    escapeHtml(formatUpxBytes(finding.packedFileSize)),
    "Complete analyzed file, including the UPX loader, PE headers, and any trailing data.",
    "peNumeric"
  ) + renderUpxRow(
    "Original file size",
    escapeHtml(formatUpxBytes(header.originalFileSize)),
    "Size of the input PE file on disk before UPX packing.",
    "peNumeric"
  ) + renderUpxRow(
    "File compression ratio",
    formatFileRatio(ratio),
    "Current packed file size divided by original file size; this is UPX's whole-file ratio.",
    "peNumeric"
  );
};

const renderFilterRows = (finding: PeUpxPackerFinding): string => {
  const header = finding.packHeader;
  const filter = `${hex(header.filter, 2)} — ${upxFilterLabel(header.filter)}`;
  return renderUpxRow(
    "Filter",
    escapeHtml(filter),
    "Reversible executable-code preprocessing applied before compression.",
    ""
  ) + renderUpxRow(
    "Filter CTO",
    `${header.filterParameter} (${hex(header.filterParameter, 2)})`,
    "Call-trick offset selected by UPX for the executable filter.",
    "peNumeric"
  );
};

export const renderUpxFindingDetails = (finding: PeUpxPackerFinding): string => {
  const header = finding.packHeader;
  const packedStart = finding.packHeaderOffset + header.headerSize;
  const packedEnd = packedStart + header.packedSize;
  return `<div class="tableWrap"><table class="table peUpxTable pePackerFinding__details">` +
    `<thead><tr><th>Field</th><th>Value</th><th>Meaning</th></tr></thead><tbody>` +
    renderUpxRow("PackHeader offset", hex(finding.packHeaderOffset, 8),
      "File offset of the validated UPX PackHeader.", "peNumeric") +
    renderUpxRow("Packed data start", hex(packedStart, 8),
      "First compressed payload byte, immediately after PackHeader.", "peNumeric") +
    renderUpxRow("Packed data end", hex(packedEnd, 8),
      "Exclusive end offset of the compressed payload.", "peNumeric") +
    renderUpxRow("UPX format", renderUpxFormatChips(header.format),
      "Executable-format identifier recorded in PackHeader; the active chip is validated.") +
    renderUpxRow("UPX version", String(header.version),
      "PackHeader format-version byte, not the UPX release number.", "peNumeric") +
    renderUpxRow("Compression", renderOptionChips(header.method, UPX_COMPRESSION_METHODS),
      "Declared method; the selected chip is the method that successfully decoded the payload.") +
    renderUpxRow("Compression level", formatCompressionLevel(header.level),
      "UPX packing-time effort preset; level 10 corresponds to --best and may be slow.",
      "peNumeric") +
    renderSizeRows(finding) + renderFilterRows(finding) +
    `</tbody></table></div>`;
};
