"use strict";

import { safe } from "../../html-utils.js";
import { toHex32 } from "../../binary-utils.js";
import type { SevenZipFileSummary, SevenZipParseResult } from "../../analyzers/sevenz/index.js";
import { FILE_FLAG_DEFS, renderFlagsOrNone } from "./flags-view.js";
import { describeCoders, describeFileType } from "./semantics.js";
import { formatRatio, formatSizeDetailed } from "./value-format.js";

const FILE_RENDER_LIMIT = 200;
// These bit positions match FILE_FLAG_DEFS from flags-view.ts.
const FILE_FLAG_DIRECTORY = 1;
const FILE_FLAG_ENCRYPTED = 2;
const FILE_FLAG_EMPTY = 4;
const FILE_FLAG_NO_STREAM = 8;
const CRC32_HEX_WIDTH = 8;
const FIRST_HUMAN_INDEX = 1;

export const renderFiles = (sevenZip: SevenZipParseResult, out: string[]): void => {
  const files = sevenZip.structure?.files || [];
  if (!files.length) return;
  const shown = files.slice(0, FILE_RENDER_LIMIT);
  const showActions = files.some(file => file.hasStream !== false && !file.isDirectory);
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
      `<th title="Logical size of the file after decoding (uncompressed size).">Uncompressed</th>` +
      `<th title="Approximate compressed size accounted to this file.">Packed</th>` +
      `<th title="Packed size divided by uncompressed size.">Ratio</th>` +
      `<th title="Folder index and coder chain that carry this file&apos;s stream.">Method</th>` +
      `<th title="CRC32 of the uncompressed file data, if present in the header.">CRC</th>` +
      `<th title="Last modification time stored in the header.">Modified</th>` +
      `<th title="File attribute mask from the header.">Attributes</th>` +
      `<th title="Convenience flags derived from header fields.">Flags</th>` +
      (showActions
        ? `<th title="Download this entry when its 7z coder pipeline is supported.">Action</th>`
        : "") +
    `</tr></thead><tbody>`
  );
  shown.forEach((file: SevenZipFileSummary) => {
    out.push(renderFileRow(file, sevenZip, showActions));
  });
  out.push(`</tbody></table>`);
  if (files.length > FILE_RENDER_LIMIT) {
    out.push(`<div class="smallNote">${files.length - FILE_RENDER_LIMIT} more entries not shown.</div>`);
  }
  out.push(`</section>`);
};

const renderFileRow = (
  file: SevenZipFileSummary,
  sevenZip: SevenZipParseResult,
  showActions: boolean
): string => {
  const folder =
    file.folderIndex != null && file.folderIndex >= 0 ? sevenZip.structure?.folders[file.folderIndex] : null;
  const methodText = folder ? renderFolderMethod(folder.index, describeCoders(folder.coders)) : "-";
  const flagMask =
    (file.isDirectory ? FILE_FLAG_DIRECTORY : 0) |
    (file.isEncrypted ? FILE_FLAG_ENCRYPTED : 0) |
    (file.isEmpty ? FILE_FLAG_EMPTY : 0) |
    (file.hasStream === false ? FILE_FLAG_NO_STREAM : 0);
  return `<tr><td>${file.index}</td><td>${safe(file.name)}</td>` +
    `<td>${safe(describeFileType(file))}</td><td>${formatSizeDetailed(file.uncompressedSize)}</td>` +
    `<td>${formatSizeDetailed(file.packedSize)}</td><td>${formatRatio(file.compressionRatio)}</td>` +
    `<td>${safe(methodText)}</td><td>${file.crc32 != null ? toHex32(file.crc32, CRC32_HEX_WIDTH) : "-"}</td>` +
    `<td>${file.modifiedTime ? safe(file.modifiedTime) : "-"}</td>` +
    `<td>${file.attributes ? safe(file.attributes) : "-"}</td>` +
    `<td>${renderFlagsOrNone(flagMask, FILE_FLAG_DEFS)}</td>${renderActionCell(file, showActions)}</tr>`;
};

const renderFolderMethod = (index: number, coderText: string): string => {
  const folderLabel = `Folder ${index + FIRST_HUMAN_INDEX}`;
  return coderText !== "-" ? `${folderLabel}: ${coderText}` : folderLabel;
};

const renderActionCell = (file: SevenZipFileSummary, showActions: boolean): string => {
  if (!showActions) return "";
  if (file.hasStream === false || file.isDirectory) return "<td>-</td>";
  if (file.extractError) return `<td><span class="smallNote">${safe(file.extractError)}</span></td>`;
  return `<td><button type="button" class="tableButton sevenZipExtractButton" ` +
    `data-sevenzip-entry="${file.index}">Extract</button></td>`;
};
