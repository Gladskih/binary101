"use strict";

import { dd, safe } from "../../html-utils.js";
import { toHex32 } from "../../binary-utils.js";
import type {
  SevenZipArchiveFlags,
  SevenZipParseResult,
  SevenZipParsedNextHeader,
  SevenZipStartHeader
} from "../../analyzers/sevenz/index.js";
import {
  formatOffset,
  formatSize,
  formatSizeDetailed
} from "./value-format.js";
import { ARCHIVE_FLAG_DEFS, renderFlagsOrNone } from "./flags-view.js";
import {
  KNOWN_METHODS,
  describeCoders,
  describeHeaderKind
} from "./semantics.js";
import { renderSignatureLayout } from "./signature.js";
import { renderFiles } from "./files-table.js";

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
      "7z format version stored in the 32-byte signature header."
    )
  );

  out.push(
    dd(
      "Start header CRC",
      toHex32(header.startHeaderCrc ?? 0, 8),
      "CRC32 over the fields that locate the main header database."
    )
  );

  const relativeOffset = header.nextHeaderOffset;
  const relativeText = relativeOffset != null ? formatOffset(relativeOffset) : "-";
  out.push(
    dd(
      "Next header offset",
      formatOffset(header.absoluteNextHeaderOffset),
      `File offset (absolute position) of the header database. Stored on disk as a UINT64 offset from the end of the signature header; the stored relative offset here is ${relativeText}.`
    )
  );

  out.push(
    dd(
      "Next header size",
      formatSize(header.nextHeaderSize),
      "Size in bytes of the encoded header database (packed size if compressed)."
    )
  );

  out.push(
    dd(
      "Next header CRC",
      toHex32((next.crc ?? header.nextHeaderCrc) ?? 0, 8),
      "CRC32 checksum of the header database after decoding."
    )
  );

  out.push(
    dd(
      "Header kind",
      safe(describeHeaderKind(next.parsed)),
      "Whether the next header is plain, encoded (compressed/encrypted), empty or unknown."
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
      "High-level properties from StreamsInfo: solid vs non-solid, header encoding and encrypted content."
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
      encodingSummary = `${parts.join("; ")} — ${note}`;
    }
    out.push(
      dd(
        "Header encoding",
        safe(encodingSummary),
        "How the header database itself is encoded (compression and/or encryption coders)."
      )
    );
  } else {
    out.push(
      dd(
        "Header encoding",
        "Plain (not encoded)",
        "Header database is stored directly at the next-header location."
      )
    );
  }

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
