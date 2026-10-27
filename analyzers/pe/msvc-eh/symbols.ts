import { COFF_SECTION_CHARACTERISTICS } from "../../coff/layout.js";
import { IMAGE_FILE_MACHINE_I386 } from "../../coff/machine.js";
import type { CoffDebugInfo } from "../../coff/debug-types.js";
import type { PeLegacyCodeViewInfo } from "../debug/legacy-codeview.js";
import type { PeWindowsCore } from "../types.js";
import type { EhFunctionSymbol } from "./types.js";
import { createCodeViewProcedureResolver } from "../debug/codeview-procedure-addresses.js";
import { getEhPersonalityName } from "./personality.js";
import type { CoffSymbol } from "../../coff/debug-types.js";
import type { PeSection } from "../types.js";
import { IMAGE_DEBUG_TYPE_OMAP_FROM_SRC, IMAGE_DEBUG_TYPE_OMAP_TO_SRC } from "../debug/types.js";

const validCoffFunction = (symbol: CoffSymbol, section: PeSection): boolean =>
  (symbol.type & 0x30) === 0x20 && symbol.nameSource !== "unresolved" && symbol.value >= 0 &&
  symbol.value < (section.virtualSize || section.sizeOfRawData) &&
  (section.characteristics & COFF_SECTION_CHARACTERISTICS.MEM_EXECUTE) !== 0;

const coffSymbols = (core: PeWindowsCore, sources: readonly CoffDebugInfo[]): EhFunctionSymbol[] =>
  sources.flatMap(info => info.symbols.flatMap(symbol => {
    const section = core.sections[symbol.sectionNumber - 1];
    // COFF derived type FUNCTION is 2 in bits 4..5; Value is section-relative.
    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#symbol-type
    if (!section || !validCoffFunction(symbol, section)) return [];
    const name = core.coff.Machine === IMAGE_FILE_MACHINE_I386 ? symbol.name.slice(1) : symbol.name;
    return getEhPersonalityName(name) ? [{ rva: section.virtualAddress + symbol.value,
      name, source: "COFF" as const }] : [];
  }));

const codeViewSymbols = (
  core: PeWindowsCore, infos: readonly PeLegacyCodeViewInfo[], entries: readonly { type: number }[]
): EhFunctionSymbol[] => infos.flatMap(info => {
  const resolve = createCodeViewProcedureResolver(info, core.sections, entries);
  return info.directories.flatMap((directory, index) => directory.subsections.flatMap(section =>
    section.data?.kind === "symbols" ? section.data.records.flatMap(symbol => {
      if (!symbol.procedure || !symbol.name || !getEhPersonalityName(symbol.name)) return [];
      const address = resolve(index, symbol.procedure);
      return address.rva === undefined ? [] : [{ rva: address.rva,
        name: symbol.name, source: "CodeView" as const }];
    }) : []));
});

export const collectEhFunctionSymbols = (
  core: PeWindowsCore, coff: readonly CoffDebugInfo[], codeview: readonly PeLegacyCodeViewInfo[],
  debugEntries: readonly { type: number }[]
): EhFunctionSymbol[] => debugEntries.some(entry => entry.type === IMAGE_DEBUG_TYPE_OMAP_TO_SRC ||
  entry.type === IMAGE_DEBUG_TYPE_OMAP_FROM_SRC) ? [] :
  [...coffSymbols(core, coff), ...codeViewSymbols(core, codeview, debugEntries)];
