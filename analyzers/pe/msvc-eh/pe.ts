import type { FileRangeReader } from "../../file-range-reader.js";
import type { PeWindowsCore } from "../types.js";
import type { PeWindowsParseResult } from "../core/parse-result.js";
import { IMAGE_DLL_CHARACTERISTICS_NO_SEH } from "../optional-header/dll-characteristics.js";
import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "../optional-header/magic.js";
import { analyzeMsvcEh } from "./index.js";
import { collectEhFunctionSymbols } from "./symbols.js";
import { collectEhLoadConfigChecks } from "./checks.js";

const functionSymbols = (core: PeWindowsCore, pe: PeWindowsParseResult) => {
  const debugEntries = pe.debug?.entries ?? [];
  return collectEhFunctionSymbols(core,
    [...debugEntries.flatMap(entry => entry.coff ? [entry.coff] : []),
      ...pe.coffDebug ? [pe.coffDebug] : []],
    [...debugEntries.flatMap(entry => entry.legacyCodeView ? [entry.legacyCodeView] : []),
      ...pe.debug?.codeViewSources?.map(source => source.legacyCodeView) ?? []], debugEntries);
};

const imageUsesNoSeh = (pe: PeWindowsParseResult): boolean =>
  (pe.opt.DllCharacteristics & IMAGE_DLL_CHARACTERISTICS_NO_SEH) !== 0 && !pe.loadcfg;

export const withPeMsvcEh = async (
  reader: FileRangeReader, core: PeWindowsCore, pe: PeWindowsParseResult
): Promise<PeWindowsParseResult> => {
  const analysis = await analyzeMsvcEh(reader, core, pe.exception, pe.imports,
    pe.exports?.entries ?? [], pe.loadcfg, functionSymbols(core, pe));
  if (!analysis) return pe;
  if (analysis.records.length && imageUsesNoSeh(pe)) {
    analysis.warnings.push("PE header sets NO_SEH, but validated Microsoft EH metadata is present.");
  }
  const result = { ...pe, msvcEh: analysis };
  if (!pe.loadcfg) return result;
  return { ...result, loadcfg: { ...pe.loadcfg, checks: [
    ...pe.loadcfg.checks ?? [], ...collectEhLoadConfigChecks(pe.loadcfg, analysis,
      pe.opt.DllCharacteristics, core.opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC ? 8 : 4)
  ] } };
};
