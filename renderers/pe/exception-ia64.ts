import type { PeExceptionDirectory } from "../../analyzers/pe/exception/types.js";
import { renderDefinitionRow, escapeHtml } from "../../html-utils.js";

export const renderIa64UnwindStatistics = (exception: PeExceptionDirectory, out: string[]): void => {
  const statistics = exception.ia64Unwind;
  if (!statistics) return;
  for (const { version, count } of statistics.versions) {
    out.push(renderDefinitionRow(`IA64 unwind version ${version} blocks`, String(count)));
  }
  for (const [label, count] of [
    ["Decoded unwind blocks with handlers", exception.handlerUnwindInfoCount],
    ["Exception-handler blocks", statistics.exceptionHandlerCount],
    ["Cleanup-handler blocks", statistics.unwindHandlerCount],
    ...Object.entries(statistics.descriptorCounts)
  ] as const) out.push(renderDefinitionRow(escapeHtml(label), String(count)));
  for (const [key, title] of [["prologue", "Prologue"], ["body", "Body"]] as const) {
    const region = statistics.regionLengths[key];
    if (region.count && region.minimumSlots != null && region.maximumSlots != null) {
      out.push(renderDefinitionRow(`IA64 ${title} region length (instruction slots)`,
        `${region.minimumSlots} to ${region.maximumSlots} across ${region.count} regions`));
    }
  }
  for (const [label, count] of Object.entries(statistics.savedRegisterRules)) {
    out.push(renderDefinitionRow(`Saved register rules: ${escapeHtml(label)}`, String(count)));
  }
  for (const [label, count] of Object.entries(statistics.registerSaveLocations)) {
    out.push(renderDefinitionRow(`IA64 register save location: ${escapeHtml(label)}`, String(count)));
  }
  for (const [label, count] of Object.entries(statistics.spillScheduleSlots)) {
    out.push(renderDefinitionRow(`P4 spill schedule slots: ${escapeHtml(label)}`, String(count)));
  }
  for (const [label, count] of Object.entries(statistics.abiContextCounts)) {
    out.push(renderDefinitionRow(`P10 ABI context: ${escapeHtml(label)}`, String(count)));
  }
  if (statistics.maximumFixedStackBytes != null) out.push(renderDefinitionRow(
    "Largest fixed stack allocation (bytes)", String(statistics.maximumFixedStackBytes)));
};
