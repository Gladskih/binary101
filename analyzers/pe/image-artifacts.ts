"use strict";

import { analyzePeGoRuntime } from "./go-runtime.js";
import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "./optional-header/magic.js";
import { analyzePeOverlay } from "./overlay.js";
import { analyzePePackers } from "./packers/index.js";
import { analyzePePayloads, subtractExplainedPeOverlay } from "./payloads.js";
import type {
  PeDebugArtifacts,
  PeDirectoryArtifacts,
  PeWindowsParseContext
} from "./parse-windows.js";

export type PeImageArtifacts = {
  overlay: Awaited<ReturnType<typeof analyzePeOverlay>>;
  packers: Awaited<ReturnType<typeof analyzePePackers>>;
  payloads: Awaited<ReturnType<typeof analyzePePayloads>>;
  goRuntime: Awaited<ReturnType<typeof analyzePeGoRuntime>>;
};

export const parsePeImageArtifacts = async (
  context: PeWindowsParseContext,
  debugResult: PeDebugArtifacts["debugResult"],
  resources: PeDirectoryArtifacts["resources"]
): Promise<PeImageArtifacts> => {
  const { file, reader, core } = context;
  const overlay = await analyzePeOverlay({
    file,
    reader,
    optionalHeaderOffset: core.optOff,
    optionalHeaderSize: core.coff.SizeOfOptionalHeader,
    sectionCount: core.coff.NumberOfSections,
    declaredSizeOfHeaders: core.opt.SizeOfHeaders,
    sections: core.sections,
    ...(core.trailingAlignmentPaddingSize
      ? { trailingAlignmentPaddingSize: core.trailingAlignmentPaddingSize }
      : {}),
    dataDirs: core.dataDirs,
    debugRawDataRanges: debugResult.rawDataRanges,
    pointerToSymbolTable: core.coff.PointerToSymbolTable,
    numberOfSymbols: core.coff.NumberOfSymbols,
    ...(core.coffStringTableSize != null
      ? { coffStringTableSize: core.coffStringTableSize }
      : {})
  });
  const [packers, goRuntime] = await Promise.all([analyzePePackers({
    reader,
    sections: core.sections,
    overlay,
    // Bun's .bun Offsets.byte_count is a usize, so it follows the PE image pointer width.
    // https://github.com/oven-sh/bun/blob/main/src/standalone_graph/StandaloneModuleGraph.zig
    imagePointerBytes: core.opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC ? 8 : 4
  }), analyzePeGoRuntime(file, reader, core)]);
  const payloads = await analyzePePayloads(file, reader, overlay, packers, resources);
  return {
    overlay: subtractExplainedPeOverlay(overlay, packers, payloads),
    packers,
    payloads,
    goRuntime
  };
};
