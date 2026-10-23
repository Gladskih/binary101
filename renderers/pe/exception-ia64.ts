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
  if (statistics.maximumFixedStackBytes != null) out.push(renderDefinitionRow(
    "Largest fixed stack allocation (bytes)", String(statistics.maximumFixedStackBytes)));
};
