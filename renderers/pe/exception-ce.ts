import type { PeExceptionDirectory, PeCeExceptionStatistics } from "../../analyzers/pe/exception/types.js";
import { renderDefinitionRow } from "../../html-utils.js";

const renderPrologs = (statistics: PeCeExceptionStatistics, out: string[]): void => {
  if (!statistics.prologs) return;
  for (const [label, count] of [
    ["Prologs with resolved lengths", statistics.prologs.count], ["Empty prologs", statistics.prologs.empty],
    ["Shortest prolog (bytes)", statistics.prologs.minimumBytes], ["Longest prolog (bytes)", statistics.prologs.maximumBytes]
  ] as const) out.push(renderDefinitionRow(label, String(count)));
};

export const renderCeExceptionStatistics = (exception: PeExceptionDirectory, out: string[]): void => {
  const statistics = exception.ceCompressed;
  if (!statistics) return;
  for (const [label, count] of [
    ["16-bit instruction entries", statistics.instruction16Count],
    ["32-bit instruction entries", statistics.instruction32Count],
    ["Unique resolved handlers", exception.handlerRvas.length],
    ["Nonzero handler data pointers", statistics.handlerDataCount]
  ] as const) out.push(renderDefinitionRow(label, String(count)));
  if (statistics.extendedEntryCount) out.push(renderDefinitionRow(
    "Entries with unresolved extended lengths", String(statistics.extendedEntryCount)));
  renderPrologs(statistics, out);
};
