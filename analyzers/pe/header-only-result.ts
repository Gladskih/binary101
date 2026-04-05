"use strict";

import type { PeHeaderParseResult } from "./index.js";
import type { PeHeaderCore } from "./types.js";

export const buildHeaderOnlyPeParseResult = (
  core: PeHeaderCore
): PeHeaderParseResult => ({
  dos: core.dos,
  signature: "PE",
  coff: core.coff,
  ...(core.coffStringTableSize != null ? { coffStringTableSize: core.coffStringTableSize } : {}),
  ...(core.trailingAlignmentPaddingSize
    ? { trailingAlignmentPaddingSize: core.trailingAlignmentPaddingSize }
    : {}),
  opt: core.opt,
  ...(core.warnings?.length ? { warnings: core.warnings } : {}),
  dirs: core.dataDirs,
  sections: core.sections,
  entrySection: core.entrySection,
  rvaToOff: core.rvaToOff,
  overlaySize: core.overlaySize,
  imageEnd: core.imageEnd,
  imageSizeMismatch: core.imageSizeMismatch,
  hasCert: false
});
