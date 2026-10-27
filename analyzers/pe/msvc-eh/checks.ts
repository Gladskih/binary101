import type { PeLoadConfig, PeLoadConfigCheck } from "../load-config/index.js";
import { IMAGE_DLL_CHARACTERISTICS_NO_SEH } from "../optional-header/dll-characteristics.js";
import { IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT } from "../load-config/guard-flags.js";
import { EH_CONTINUATION_LAYOUT } from "../load-config/eh-continuation-layout.js";
import type { MsvcEhAnalysis } from "./types.js";

const continuationTargets = (analysis: MsvcEhAnalysis): number[] => [...new Set(
  analysis.records.flatMap(record => [
    ...record.functionInfo?.tryBlocks.flatMap(block =>
      block.handlers.flatMap(handler => handler.continuationRvas)) ?? [],
    ...record.scopes?.flatMap(scope => scope.targetRva ? [scope.targetRva] : []) ?? []
  ])
)];

const completeContinuationTable = (loadConfig: PeLoadConfig): boolean => {
  const table = loadConfig.tables?.guardEhContinuation;
  if (!table) return loadConfig.GuardEHContinuationCount === 0;
  return !table.truncated && !table.warnings?.length &&
    table.entries.length === loadConfig.GuardEHContinuationCount &&
    table.declaredCount === loadConfig.GuardEHContinuationCount;
};

const readableContinuationFields = (loadConfig: PeLoadConfig, pointerSize: 4 | 8): boolean =>
  // winnt.h IMAGE_LOAD_CONFIG_DIRECTORY32/64: count ends at these documented offsets.
  // https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/Object/COFF.h
  loadConfig.Size >= EH_CONTINUATION_LAYOUT[pointerSize].count + pointerSize && !loadConfig.warnings?.length;

const continuationCheck = (loadConfig: PeLoadConfig, targets: number[]): PeLoadConfigCheck => {
  const entries = new Set(loadConfig.tables?.guardEhContinuation?.entries.map(entry => entry.rva));
  const missing = targets.filter(rva => !entries.has(rva));
  return { status: missing.length ? "fail" : "pass", title: "Microsoft EH continuation targets",
    detail: missing.length
      ? `Confirmed EH continuation RVA(s) absent from the complete advertised GuardEHContinuationTable: ${missing.map(rva => `0x${rva.toString(16)}`).join(", ")}.`
      : `${targets.length} explicit EH continuation target(s) occur in GuardEHContinuationTable.`,
    source: "https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-eh-continuation-metadata" };
};

export const collectEhLoadConfigChecks = (
  loadConfig: PeLoadConfig, analysis: MsvcEhAnalysis, dllCharacteristics: number,
  pointerSize: 4 | 8 = 8
): PeLoadConfigCheck[] => {
  const checks: PeLoadConfigCheck[] = [];
  // PE IMAGE_DLLCHARACTERISTICS_NO_SEH applies to the image, not just SafeSEH.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#dll-characteristics
  if (analysis.records.length && (dllCharacteristics & IMAGE_DLL_CHARACTERISTICS_NO_SEH)) checks.push({ status: "fail",
    title: "Confirmed Microsoft EH vs NO_SEH",
    detail: "NO_SEH is set, but validated Microsoft-compatible exception-handling metadata is present." });
  // /guard:ehcont's absence is not a contradiction. An advertised empty table is different.
  // https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-eh-continuation-metadata
  const targets = continuationTargets(analysis);
  if (!(loadConfig.GuardFlags & IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT) || !targets.length) return checks;
  // winnt.h IMAGE_LOAD_CONFIG_DIRECTORY32/64: never mistake defaulted unread fields for zero.
  if (!readableContinuationFields(loadConfig, pointerSize) || !completeContinuationTable(loadConfig)) {
    checks.push({ status: "info", title: "Microsoft EH continuation cross-check",
      detail: "The advertised EH continuation table is incomplete; membership cannot be established." });
    return checks;
  }
  checks.push(continuationCheck(loadConfig, targets));
  return checks;
};
