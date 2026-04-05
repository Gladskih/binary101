"use strict";

import type { PeCodeViewEntry, PeDebugDirectoryEntry } from "./debug-directory.js";
import type { PeInstructionSetReport } from "./disassembly.js";
import type { PeImportLinkingResult } from "./import-linking.js";
import type { PeImportParseResult } from "./imports.js";
import type { PeIatDirectory } from "./iat-directory.js";
import type { PeArchitectureDirectory } from "./architecture-directory.js";
import type { PeGlobalPtrDirectory } from "./globalptr-directory.js";
import type { PeLoadConfig } from "./load-config/index.js";
import type { PeResources } from "./resources/index.js";
import type { PeClrHeader } from "./clr/index.js";
import type { ParsedSecurityDirectory } from "./security.js";
import type { PeCore, PeDataDirectory, PeRomOptionalHeader, PeSection, PeTlsDirectory, PeWindowsOptionalHeader, RvaToOffset } from "./types.js";
import type { parseExportDirectory } from "./exports.js";
import type { parseBaseRelocations } from "./reloc.js";
import type { parseExceptionDirectory } from "./exception.js";
import type { parseBoundImports } from "./bound-imports.js";
import type { parseDelayImports32 } from "./delay-imports.js";
import { ROM_OPTIONAL_HEADER_MAGIC } from "./optional-header-magic.js";

export interface PeDebugSection {
  entry: PeCodeViewEntry | null;
  entries?: PeDebugDirectoryEntry[];
  warning?: string;
  rawDataRanges?: Array<{ start: number; end: number }>;
}

interface PeParseResultBase {
  dos: PeCore["dos"];
  signature: "PE";
  coff: PeCore["coff"];
  coffStringTableSize?: number;
  trailingAlignmentPaddingSize?: number;
  opt: PeRomOptionalHeader | PeWindowsOptionalHeader | null;
  warnings?: string[];
  dirs: PeDataDirectory[];
  sections: PeSection[];
  entrySection: PeCore["entrySection"];
  rvaToOff: RvaToOffset;
  overlaySize: number;
  imageEnd: number;
  imageSizeMismatch: boolean;
  hasCert: boolean;
}

export interface PeWindowsParseResult extends PeParseResultBase {
  debug: PeDebugSection | null;
  opt: PeWindowsOptionalHeader;
  imports: PeImportParseResult;
  loadcfg: PeLoadConfig | null;
  exports: Awaited<ReturnType<typeof parseExportDirectory>>;
  tls: PeTlsDirectory | null;
  reloc: Awaited<ReturnType<typeof parseBaseRelocations>>;
  exception: Awaited<ReturnType<typeof parseExceptionDirectory>>;
  boundImports: Awaited<ReturnType<typeof parseBoundImports>>;
  delayImports: Awaited<ReturnType<typeof parseDelayImports32>>;
  clr: PeClrHeader | null;
  security: ParsedSecurityDirectory | null;
  iat: PeIatDirectory | null;
  importLinking: PeImportLinkingResult | null;
  architecture?: PeArchitectureDirectory | null;
  globalPtr?: PeGlobalPtrDirectory | null;
  resources: PeResources | null;
  disassembly?: PeInstructionSetReport;
}

export interface PeHeaderParseResult extends PeParseResultBase {
  opt: PeRomOptionalHeader | null;
}

export type PeParseResult = PeWindowsParseResult | PeHeaderParseResult;

export const isPeWindowsParseResult = (
  pe: PeParseResult
): pe is PeWindowsParseResult =>
  pe.opt != null && pe.opt.Magic !== ROM_OPTIONAL_HEADER_MAGIC;

export const isPeRomParseResult = (
  pe: PeParseResult
): pe is PeHeaderParseResult & { opt: PeRomOptionalHeader } =>
  pe.opt?.Magic === ROM_OPTIONAL_HEADER_MAGIC;
