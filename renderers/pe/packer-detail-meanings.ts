"use strict";

const PACKER_DETAIL_MEANINGS: Readonly<Record<string, string>> = {
  "Compressed header length": "Declared compressed size of the NSIS header block.",
  "firstheader offset": "File offset of the validated NSIS first header.",
  "Flags": "Decoded format-specific flags.",
  "Following data length": "Declared size of installer data following the first header.",
  "Installer data range": "Validated file range covered by the NSIS installer data."
};

export const packerDetailMeaning = (label: string): string =>
  PACKER_DETAIL_MEANINGS[label] ?? "Additional analyzer-specific metadata.";
