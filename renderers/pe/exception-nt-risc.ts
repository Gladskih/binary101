import type { PeExceptionDirectory } from "../../analyzers/pe/exception/types.js";
import { renderDefinitionRow } from "../../html-utils.js";

const renderPrologs = (ex: PeExceptionDirectory, out: string[]): void => {
  if (!ex.riscPrologs) return;
  for (const [label, count] of [
    ["Prologs with resolved boundaries", ex.riscPrologs.count], ["Empty prologs", ex.riscPrologs.empty],
    ["Shortest prolog (bytes)", ex.riscPrologs.minimumBytes], ["Longest prolog (bytes)", ex.riscPrologs.maximumBytes]
  ] as const) out.push(renderDefinitionRow(label, String(count)));
};

export const renderNtRiscStatistics = (ex: PeExceptionDirectory, out: string[]): void => {
  if (ex.alphaPrologs) {
    if (ex.alphaPrologs.resolvedSecondaryRanges) out.push(renderDefinitionRow(
      "Secondary ranges with known primary procedures", String(ex.alphaPrologs.resolvedSecondaryRanges),
      "Matches a primary procedure start using the early Alpha NT scheme. Other secondary ABIs remain unresolved."));
    if (ex.alphaPrologs.unresolvedSecondaryRanges) out.push(renderDefinitionRow(
      "Secondary ranges with missing primary procedures", String(ex.alphaPrologs.unresolvedSecondaryRanges)));
  } else {
    const unresolved = ex.beginRvas.length - (ex.riscPrologs?.count ?? 0);
    if (unresolved > 0) out.push(renderDefinitionRow("Ranges with unresolved inline metadata", String(unresolved)));
  }
  renderPrologs(ex, out);
  ex.riscExceptionModes?.forEach((count, mode) => {
    if (count) out.push(renderDefinitionRow(`Exception mode ${mode}`, String(count),
      "Compiler-recorded exception-reporting mode. Named meanings are not established for every ABI."));
  });
};
