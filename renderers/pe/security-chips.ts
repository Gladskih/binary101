"use strict";

import { safe } from "../../html-utils.js";

export type NamedChipOption = [string, string, string];

export const CMS_CONTENT_TYPES: NamedChipOption[] = [
  ["PKCS#7 data", "PKCS#7 data", "CMS ContentInfo data payload."],
  ["PKCS#7 signedData", "PKCS#7 signedData", "CMS SignedData content type."]
];

export const AUTHENTICODE_PAYLOAD_TYPES: NamedChipOption[] = [[
  "SPC_INDIRECT_DATA",
  "SPC_INDIRECT_DATA",
  "Authenticode indirect-data payload with the file digest."
]];

export const DIGEST_ALGORITHM_TYPES: NamedChipOption[] = [
  ["md5", "md5", "MD5 digest algorithm."],
  ["sha1", "sha1", "SHA-1 digest algorithm."],
  ["sha224", "sha224", "SHA-224 digest algorithm."],
  ["sha256", "sha256", "SHA-256 digest algorithm."],
  ["sha384", "sha384", "SHA-384 digest algorithm."],
  ["sha512", "sha512", "SHA-512 digest algorithm."],
  ["sha512/224", "sha512/224", "SHA-512/224 digest algorithm."]
];

const normalizeChipValue = (value: string): string => value.trim().toLowerCase();

export const renderNamedOptionChips = (
  values: string[],
  options: NamedChipOption[]
): string => {
  const selected = new Set(values.map(normalizeChipValue));
  const known = new Set(options.map(([value]) => normalizeChipValue(value)));
  const chips = options.map(([value, label, description]) => {
    const chipClass = selected.has(normalizeChipValue(value)) ? "opt sel" : "opt dim";
    return `<span class="${chipClass}" title="${safe(description)}">${safe(label)}</span>`;
  });
  values
    .filter(value => !known.has(normalizeChipValue(value)))
    .forEach(value => chips.push(`<span class="opt sel mono">${safe(value)}</span>`));
  return `<div class="optionsRow">${chips.join("")}</div>`;
};
