import type { PeWindowsParseResult } from "./core/parse-result.js";
import type { SanitizerDependency, SanitizerEvidence, SanitizerSymbol } from "../sanitizers/types.js";
import type { CoffDebugInfo } from "../coff/debug-types.js";
import { analyzeSanitizerEvidence } from "../sanitizers/evidence.js";
import { SANITIZER_ABI_SYMBOLS } from "../sanitizers/abi-catalog.js";

const normalizedName = (pe: PeWindowsParseResult, name: string): string =>
  // IMAGE_FILE_MACHINE_I386=0x14c; cdecl C names gain one underscore in COFF.
  // https://learn.microsoft.com/en-us/cpp/build/reference/decorated-names
  pe.coff.Machine === 0x14c && name.startsWith("___") ? name.slice(1) : name;

const peDependencies = (pe: PeWindowsParseResult): SanitizerDependency[] => [
  ...(!pe.imports.warning ? pe.imports.entries.map(entry =>
    ({ name: entry.dll, source: "PE import DLL" })) : []),
  ...(!pe.delayImports?.warning ? (pe.delayImports?.entries ?? []).map(entry =>
    ({ name: entry.name, source: "PE delay-load DLL" })) : [])
];

function* importedSymbols(pe: PeWindowsParseResult): IterableIterator<SanitizerSymbol> {
  if (!pe.imports.warning) {
    for (const entry of pe.imports.entries) {
      if (!entry.thunkTableTerminated || entry.lookupSource === "missing") continue;
      for (const fn of entry.functions) {
        if (fn.name) yield { name: fn.name, kind: "reference",
          source: `PE imports: ${entry.dll}` };
      }
    }
  }
  if (!pe.delayImports?.warning) {
    for (const entry of pe.delayImports?.entries ?? []) {
      for (const fn of entry.functions) {
        if (fn.name) yield { name: fn.name, kind: "reference",
          source: `PE delay imports: ${entry.name}` };
      }
    }
  }
}

const isExecutableRva = (pe: PeWindowsParseResult, rva: number): boolean =>
  // IMAGE_SCN_MEM_EXECUTE=0x20000000 (PE/COFF section flags).
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
  Number.isSafeInteger(rva) && rva > 0 && pe.rvaToOff(rva) != null &&
  pe.sections.some(section => (section.characteristics & 0x20000000) !== 0 &&
    rva >= section.virtualAddress && rva - section.virtualAddress < section.sizeOfRawData);

function* coffSymbols(pe: PeWindowsParseResult, debug: CoffDebugInfo | undefined,
  source: string): IterableIterator<SanitizerSymbol> {
  if (!debug || debug.warnings?.length) return;
  for (const record of debug.symbols) {
    if (record.nameSource === "unresolved") continue;
    const name = normalizedName(pe, record.name);
    if (!SANITIZER_ABI_SYMBOLS.has(name)) continue;
    const section = pe.sections[record.sectionNumber - 1];
    // Function Type=0x20; EXTERNAL/STATIC storage classes=2/3 (PE/COFF spec).
    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-symbol-table
    if (section && [2, 3].includes(record.storageClass) &&
      (record.type & 0x30) === 0x20 && record.value >= 0 &&
      record.value < section.sizeOfRawData &&
      isExecutableRva(pe, section.virtualAddress + record.value)) {
      yield { name: record.name, kind: "definition", source };
    }
  }
}

function* definedSymbols(pe: PeWindowsParseResult): IterableIterator<SanitizerSymbol> {
  if (pe.exports && !pe.exports.issues.length) {
    for (const entry of pe.exports.entries) {
      if (entry.forwarder || !isExecutableRva(pe, entry.rva)) continue;
      for (const name of entry.names) yield { name,
        kind: "definition", source: "PE exports" };
    }
  }
  yield* coffSymbols(pe, pe.coffDebug, "PE COFF symbols");
  for (const entry of pe.debug?.entries ?? []) {
    yield* coffSymbols(pe, entry.coff, "PE debug COFF symbols");
  }
}

function* peSymbols(pe: PeWindowsParseResult): IterableIterator<SanitizerSymbol> {
  yield* importedSymbols(pe);
  yield* definedSymbols(pe);
}

const goRaceEvidence = (pe: PeWindowsParseResult): SanitizerEvidence[] => {
  // These assembler entry points exist only in race_*.s (build tag race), unlike race0.go stubs.
  // https://github.com/golang/go/blob/master/src/runtime/race_amd64.s
  const names = new Set((pe.goRuntime?.functions ?? []).filter(fn =>
    fn.name === "runtime.raceread" || fn.name === "runtime.racewrite").map(fn => fn.name));
  return names.has("runtime.raceread") && names.has("runtime.racewrite")
    ? ["runtime.raceread", "runtime.racewrite"].map(name => ({
      tool: "Go race detector", kind: "definition", source: "Validated Go function metadata", name
    })) : [];
};

export const analyzePeSanitizers = (pe: PeWindowsParseResult): SanitizerEvidence[] =>
  [...analyzeSanitizerEvidence(peDependencies(pe), peSymbols(pe), name => normalizedName(pe, name)),
    ...goRaceEvidence(pe)];
