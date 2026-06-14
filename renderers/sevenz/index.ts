"use strict";

import { renderDefinitionRow, escapeHtml } from "../../html-utils.js";
import { toHex32 } from "../../binary-utils.js";
import type {
  SevenZipArchiveFlags,
  SevenZipParseResult,
  SevenZipParsedNextHeader,
  SevenZipStartHeader
} from "../../analyzers/sevenz/index.js";
import { formatOffset, formatSize, formatSizeDetailed } from "./value-format.js";
import { ARCHIVE_FLAG_DEFS, renderFlagsOrNone } from "./flags-view.js";
import { KNOWN_METHODS, describeCoders, describeHeaderKind } from "./semantics.js";
import { renderSignatureLayout } from "./signature.js";
import { renderFiles } from "./files-table.js";

const describeHeaderEncoding = (
  sevenZip: SevenZipParseResult,
  next: { parsed?: SevenZipParsedNextHeader }
): string => {
  if (next.parsed?.kind !== "encoded") return "Plain (not encoded)";
  const folders = sevenZip.headerEncoding?.coders || [];
  if (!folders.length) return "Encoded header; details unavailable.";
  const parts = folders.map(folder => {
    const chain = describeCoders(folder.coders);
    const encFlag = folder.isEncrypted ? "encrypted" : "not encrypted";
    return `Folder ${folder.index + 1}: ${chain || "(no coders)"} (${encFlag})`;
  });
  const note = sevenZip.headerEncoding?.hasEncryptedHeader
    ? "header streams appear encrypted."
    : "header streams appear compressed but not encrypted.";
  return `${parts.join("; ")} â€” ${note}`;
};

const renderHeaderEncodingRow = (
  sevenZip: SevenZipParseResult,
  next: { parsed?: SevenZipParsedNextHeader }
): string =>
  renderDefinitionRow(
    "Header encoding",
    escapeHtml(describeHeaderEncoding(sevenZip, next)),
    next.parsed?.kind === "encoded"
      ? "How the header database itself is encoded (compression and/or encryption coders)."
      : "Header database is stored directly at the next-header location."
  );

const renderOverview = (sevenZip: SevenZipParseResult, out: string[]): void => {
  const header = (sevenZip.startHeader || {}) as Partial<SevenZipStartHeader>;
  const next = (sevenZip.nextHeader || {}) as {
    crc?: number;
    parsed?: SevenZipParsedNextHeader;
  };
  const flags = sevenZip.structure?.archiveFlags as SevenZipArchiveFlags | undefined;
  const versionText =
    header.versionMajor != null && header.versionMinor != null
      ? `${header.versionMajor}.${header.versionMinor}`
      : "-";
  const relativeText =
    header.nextHeaderOffset != null ? formatOffset(header.nextHeaderOffset) : "-";
  out.push(`<section>`);
  out.push(`<h4 style="margin:0 0 .5rem 0;font-size:.9rem">7z overview</h4>`);
  out.push(`<dl>`);
  out.push(
    renderDefinitionRow(
      "Version",
      versionText,
      "7z format version stored in the 32-byte signature header."
    )
  );
  out.push(
    renderDefinitionRow(
      "Start header CRC",
      toHex32(header.startHeaderCrc ?? 0, 8),
      "CRC32 over the fields that locate the main header database."
    )
  );
  out.push(
    renderDefinitionRow(
      "Next header offset",
      formatOffset(header.absoluteNextHeaderOffset),
      `File offset (absolute position) of the header database. Stored on disk as a UINT64 offset from the end of the signature header; the stored relative offset here is ${relativeText}.`
    )
  );
  out.push(
    renderDefinitionRow(
      "Next header size",
      formatSize(header.nextHeaderSize),
      "Size in bytes of the encoded header database (packed size if compressed)."
    )
  );
  out.push(
    renderDefinitionRow(
      "Next header CRC",
      toHex32((next.crc ?? header.nextHeaderCrc) ?? 0, 8),
      "CRC32 checksum of the header database after decoding."
    )
  );
  out.push(
    renderDefinitionRow(
      "Header kind",
      escapeHtml(describeHeaderKind(next.parsed)),
      "Whether the next header is plain, encoded (compressed/encrypted), empty or unknown."
    )
  );
  out.push(
    renderDefinitionRow(
      "Archive flags",
      flags
        ? renderFlagsOrNone(
            (flags.isSolid ? 1 : 0) |
              (flags.isHeaderEncrypted ? 2 : 0) |
              (flags.hasEncryptedContent ? 4 : 0),
            ARCHIVE_FLAG_DEFS
          )
        : "-",
      "High-level properties from StreamsInfo: solid vs non-solid, header encoding and encrypted content."
    )
  );
  out.push(renderHeaderEncodingRow(sevenZip, next));
  out.push(`</dl>`);
  out.push(`</section>`);
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
    const encrypted = folder.isEncrypted ? "Yes" : "No";
    out.push(
      `<tr><td>${index + 1}</td><td>${escapeHtml(coderText)}</td>` +
        `<td>${formatSizeDetailed(folder.unpackSize)}</td>` +
        `<td>${formatSizeDetailed(folder.packedSize)}</td><td>${encrypted}</td></tr>`
    );
  });
  out.push(`</tbody></table>`);
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
    out.push(
      `<li>${escapeHtml(name)} (id ${escapeHtml(id)})${
        description ? ` - ${escapeHtml(description)}` : ""
      }</li>`
    );
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
  issues.forEach(issue => out.push(`<li>${escapeHtml(issue)}</li>`));
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
