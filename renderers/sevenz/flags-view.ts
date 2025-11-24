"use strict";

import { safe } from "../../html-utils.js";
import { toHex32 } from "../../binary-utils.js";

export const ARCHIVE_FLAG_DEFS: Array<[number, string, string]> = [
  [1, "Solid", "Solid compression: multiple files share a single compressed stream."],
  [2, "Header enc", "Header is stored in encoded form (often encrypted or compressed)."],
  [4, "Encrypted data", "At least one folder appears to use AES-256 encryption."]
];

export const FILE_FLAG_DEFS: Array<[number, string, string]> = [
  [1, "dir", "Directory entry; represents a folder rather than file data."],
  [2, "enc", "File data (or its folder) appears to be encrypted."],
  [4, "empty", "Zero-length file data after decompression."],
  [8, "no-stream", "Entry has no associated data stream (metadata only or anti-item)."]
];

export const renderFlagsOrNone = (
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

