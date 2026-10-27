import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeWindowsCore } from "../types.js";
import type { PeExceptionDirectory, PeLanguageHandler } from "../exception/types.js";
import type { PeImportParseResult } from "../imports/index.js";
import type { PeExportEntry } from "../directories/exports.js";
import type { EhFunctionInfo, EhFunctionSymbol, EhImage, MsvcEhAnalysis, MsvcEhRecord } from "./types.js";
import { IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_ARMNT,
  IMAGE_FILE_MACHINE_I386 } from "../../coff/machine.js";
import { PE32_OPTIONAL_HEADER_MAGIC, PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "../optional-header/magic.js";
import { createEhImage } from "./image.js";
import { createEhPersonalityResolver, type EhPersonality } from "./personality.js";
import { parseFh3 } from "./fh3.js";
import { parseFh4 } from "./fh4.js";
import { parseSehScopes } from "./seh.js";
import { validateEhFunctionLinks } from "./validation.js";
import { analyzeX86Eh } from "./x86.js";
import type { PeLoadConfig } from "../load-config/index.js";
import { createEhFunctionCoverage } from "./function-coverage.js";

const compatibleHeader = (core: PeWindowsCore): boolean => {
  // Do not treat ARM64EC/X's mixed code as a single ISA without a proven code map.
  // https://learn.microsoft.com/en-us/windows/arm/arm64ec-abi
  if (core.coff.Machine === IMAGE_FILE_MACHINE_I386 || core.coff.Machine === IMAGE_FILE_MACHINE_ARMNT) {
    return core.opt.Magic === PE32_OPTIONAL_HEADER_MAGIC;
  }
  return (core.coff.Machine === IMAGE_FILE_MACHINE_AMD64 || core.coff.Machine === IMAGE_FILE_MACHINE_ARM64) &&
    core.opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC;
};

const validSeed = (image: EhImage, seed: PeLanguageHandler): boolean =>
  image.code(seed.handlerRva) && (seed.functionRanges?.length ?? 0) > 0 &&
  seed.functionRanges!.every(range => image.code(range.begin, range.end - range.begin));

const structuralFh3Evidence = (info: EhFunctionInfo, covers: ((rva: number) => boolean) | null): boolean =>
  covers != null && validateEhFunctionLinks(info, covers) && info.unwindActions.length > 0 &&
  (info.tryBlocks.length > 0 || info.unwindActions.some(action => action.actionRva !== 0));

const seedEvidence = (seed: PeLanguageHandler, personality: EhPersonality | null) => ({
  unwindInfoRva: seed.unwindInfoRva, handlerRva: seed.handlerRva,
  functionRvas: seed.functionRanges!.map(range => range.begin),
  ...(personality ? { personality: personality.name } : {})
});

const nonemptyAnalysis = (analysis: MsvcEhAnalysis): MsvcEhAnalysis | null =>
  analysis.records.length || analysis.warnings.length ? analysis : null;

const cppRecord = async (
  image: EhImage, seed: PeLanguageHandler, personality: EhPersonality | null,
  covers: ((rva: number) => boolean) | null
): Promise<MsvcEhRecord | null> => {
  const functionInfo = await readLinkedFunctionInfo(image, seed, personality, covers);
  return functionInfo ? { ...seedEvidence(seed, personality), functionInfo,
    evidence: personality?.evidence ?? "UNWIND_INFO linkage, FH3 magic and complete metadata graph; handler identity unresolved" }
    : null;
};

const readLinkedFunctionInfo = async (
  image: EhImage, seed: PeLanguageHandler, personality: EhPersonality | null,
  covers: ((rva: number) => boolean) | null
): Promise<EhFunctionInfo | null> => {
  const pointer = await image.read(seed.dataRva, Uint32Array.BYTES_PER_ELEMENT);
  if (!pointer) return null;
  const infoRva = pointer.getUint32(0, true);
  const info = personality?.name === "__CxxFrameHandler4"
    ? await parseFh4(image, infoRva, seed.functionRanges![0]!.begin) : await parseFh3(image, infoRva);
  if (!info) return null;
  // FH4 has no signature: never attempt it without identity. FH3's fallback requires
  // its magic, a complete graph, substantive EH data, and independent .pdata IP coverage.
  // https://devblogs.microsoft.com/cppblog/making-cpp-exception-handling-smaller-x64/
  return personality || structuralFh3Evidence(info, covers) ? info : null;
};

const parseRecord = async (
  image: EhImage, seed: PeLanguageHandler, personality: EhPersonality | null,
  covers: ((rva: number) => boolean) | null
): Promise<MsvcEhRecord | null> => {
  if (!validSeed(image, seed)) return null;
  if (personality?.name === "_except_handler3" || personality?.name === "_except_handler4") return null;
  if (personality?.name === "__C_specific_handler") {
    const scopes = await parseSehScopes(image, seed.dataRva);
    return scopes ? { ...seedEvidence(seed, personality), scopeTableRva: seed.dataRva,
      evidence: personality.evidence, scopes } : null;
  }
  return cppRecord(image, seed, personality, covers);
};

const analyzeContributions = async (
  image: EhImage, seed: PeLanguageHandler, personality: EhPersonality | null,
  covers: ((rva: number) => boolean) | null
): Promise<MsvcEhAnalysis> => {
  const records: MsvcEhRecord[] = [], warnings: string[] = [];
  // FH4 COMDAT folding shares bytes but keeps function-relative address interpretation.
  // https://devblogs.microsoft.com/cppblog/making-cpp-exception-handling-smaller-x64/
  const contributions = personality?.name === "__CxxFrameHandler4"
    ? fh4Contributions(seed) : [seed];
  for (const contribution of contributions) {
    const record = await parseRecord(image, contribution, personality, covers);
    if (record) {
      records.push(record);
      for (const warning of recordWarnings(record, contribution, covers)) warnings.push(warning);
    } else if (personality) warnings.push(
      `${personality.name} at RVA 0x${seed.handlerRva.toString(16)} is referenced by unwind RVA 0x${seed.unwindInfoRva.toString(16)}, but its metadata or function links were not validated (malformed, truncated or unsupported layout).`
    );
  }
  return { records, warnings };
};

const recordWarnings = (
  record: MsvcEhRecord, seed: PeLanguageHandler, covers: ((rva: number) => boolean) | null
): string[] => {
  const warnings: string[] = [];
  if (record.functionInfo && covers && !validateEhFunctionLinks(record.functionInfo, covers)) {
    warnings.push(`Validated FH${record.functionInfo.version} metadata at RVA 0x${record.functionInfo.rva.toString(16)} contains IP-to-state addresses outside the decoded runtime function ranges.`);
  }
  if (record.scopes?.some(scope => !seed.functionRanges?.some(range =>
    scope.beginRva >= range.begin && scope.endRva <= range.end))) {
    warnings.push(`Validated SEH scope table at RVA 0x${seed.dataRva.toString(16)} contains ranges outside the referencing runtime function(s).`);
  }
  return warnings;
};

const fh4Contributions = (seed: PeLanguageHandler): PeLanguageHandler[] =>
  // Chained secondary ranges do not prove the FunctionEntry base supplied to FH4.
  // Decode only direct owners; the graph still retains secondary-to-handler linkage.
  // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#chained-unwind-info-structures
  // MSVC 14.51 risctrnsctrl.cpp uses DispatcherContext.FunctionEntry->BeginAddress.
  (seed.functionRanges ?? []).filter(range => range.sourceUnwindInfoRva === undefined ||
    range.sourceUnwindInfoRva === seed.unwindInfoRva).map(range => ({ ...seed, functionRanges: [range] }));

export const analyzeMsvcEh = async (
  reader: FileRangeReader, core: PeWindowsCore, exception: PeExceptionDirectory | null,
  imports: PeImportParseResult | null, exports: PeExportEntry[], loadConfig?: PeLoadConfig | null,
  symbols: readonly EhFunctionSymbol[] = []
): Promise<MsvcEhAnalysis | null> => {
  if (!compatibleHeader(core)) return null;
  const image = createEhImage(reader, core);
  const resolve = createEhPersonalityResolver(image, imports, exports, symbols);
  if (core.coff.Machine === IMAGE_FILE_MACHINE_I386) {
    const result = await analyzeX86Eh(image, resolve, loadConfig);
    return nonemptyAnalysis(result);
  }
  const records: MsvcEhRecord[] = [];
  const warnings: string[] = [];
  const covers = createEhFunctionCoverage(exception);
  for (const seed of exception?.languageHandlers ?? []) {
    const personality = await resolve(seed.handlerRva);
    const result = await analyzeContributions(image, seed, personality, covers);
    for (const record of result.records) records.push(record);
    for (const warning of result.warnings) warnings.push(warning);
  }
  return nonemptyAnalysis({ records, warnings });
};
