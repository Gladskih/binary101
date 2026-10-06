import type { ElfDynamicSymbol, ElfParseResult } from "../../analyzers/elf/types.js";
import type { ElfStaticSymbol } from "../../analyzers/elf/symbol-tables.js";
import { relocationFixture } from "./elf-relocations.js";
import { createBasePe, createPeSection } from "./pe-renderer-headers-fixture.js";
import type { PeImportEntry } from "../../analyzers/pe/imports/index.js";
import type { CoffDebugInfo } from "../../analyzers/coff/debug-types.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/core/parse-result.js";

export const sanitizerElf = (): ElfParseResult => {
  const elf = relocationFixture().elf;
  // SHF_EXECINSTR=4, SHT_PROGBITS=1; ET_REL symbols are relative to their section.
  // https://gabi.xinuos.com/elf/03-sheader.html
  elf.sections[1] = { ...elf.sections[1]!, flags: 4n, type: 1, size: 64n };
  return elf;
};

export const sanitizerStaticSymbol = (name: string): ElfStaticSymbol => ({
  name, value: 1n, size: 1n, info: 18, other: 0, sectionIndex: 1
  // st_info=0x12: STB_GLOBAL=1, STT_FUNC=2. gABI symbol table specification.
});

export const sanitizerDynamicSymbol = (name: string): ElfDynamicSymbol => ({
  index: 1, name, value: 0n, size: 0n, bind: 1, bindName: "GLOBAL", type: 2,
  typeName: "FUNC", visibility: 0, visibilityName: "DEFAULT", shndx: 0
});

export const sanitizerImport = (dll: string, names: string[]): PeImportEntry => ({
  dll, originalFirstThunkRva: 0, timeDateStamp: 0, forwarderChain: 0, firstThunkRva: 0,
  lookupSource: "import-lookup-table", thunkTableTerminated: true,
  functions: names.map(name => ({ name }))
});

export const sanitizerPe = () => {
  const pe = createBasePe();
  pe.sections = [createPeSection(".text", { virtualAddress: 4096,
    pointerToRawData: 512, virtualSize: 64, sizeOfRawData: 64 })];
  pe.sections[0]!.characteristics = 0x20000020; // IMAGE_SCN_MEM_EXECUTE | CNT_CODE (winnt.h).
  pe.rvaToOff = rva => rva >= 4096 && rva < 4160 ? 512 + rva - 4096 : null;
  return pe;
};

export const sanitizerCoffDebug = (): CoffDebugInfo => ({
  source: "coff-header", symbolTableOffset: 0, stringTableOffset: null, lineNumberBlocks: [],
  symbols: ["__asan_init", "__asan_report_load4"].map((name, index) => ({
    index, name, nameSource: "short", value: index, sectionNumber: 1,
    type: 0x20, storageClass: 2, auxiliarySymbolCount: 0, auxiliaryRecords: []
    // COFF Type: function=0x20, storage class: external=2 (PE/COFF specification).
  }))
});

export const sanitizerExports = (): NonNullable<PeWindowsParseResult["exports"]> => ({
  flags: 0, timestamp: 0, version: 0, dllName: "runtime.dll", Base: 1,
  NumberOfFunctions: 2, NumberOfNames: 2, namePointerTable: 0, ordinalTable: 0, issues: [],
  entries: ["__asan_init", "__asan_report_load4"].map((name, index) => ({
    ordinal: index + 1, rva: 4096 + index, names: [name]
  }))
});
