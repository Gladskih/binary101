"use strict";

import type { PeParseResult } from "./index.js";
import type { PeCore } from "./types.js";

export const buildHeaderOnlyPeParseResult = (core: PeCore): PeParseResult => ({
  debug: null,
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
  imports: { entries: [] },
  loadcfg: null,
  exports: null,
  tls: null,
  reloc: null,
  exception: null,
  boundImports: null,
  delayImports: null,
  clr: null,
  security: null,
  iat: null,
  architecture: null,
  globalPtr: null,
  resources: null,
  overlaySize: core.overlaySize,
  imageEnd: core.imageEnd,
  imageSizeMismatch: core.imageSizeMismatch,
  hasCert: false
});
