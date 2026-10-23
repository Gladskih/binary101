import type { PeLegacyCodeViewInfo, LegacyCodeViewData } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewTable } from "./legacy-codeview-tables.js";
import { iterateLegacyCodeViewSymbols } from "./legacy-codeview-symbol-walk.js";

interface DiscardedStatistics { records: number; sourceLines: number; first: number; last: number; }

const appendSection = (data: LegacyCodeViewData, table: LegacyCodeViewTable,
  directory: number, module: number): void => {
  const counts = new Map<number, DiscardedStatistics>();
  for (const { record } of iterateLegacyCodeViewSymbols(data)) {
    if (!record.discarded) continue;
    const group = counts.get(record.discarded.reason) ??
      { records: 0, sourceLines: 0, first: Infinity, last: -Infinity };
    group.records++;
    // C7Discarded: FILEID 0xffffffff means the source-line fields are absent.
    // https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/cvdump/dumpsym7.cpp#L6209
    if (record.discarded.fileId !== 0xffffffff) {
      group.sourceLines++;
      group.first = Math.min(group.first, record.discarded.line);
      group.last = Math.max(group.last, record.discarded.line);
    }
    counts.set(record.discarded.reason, group);
  }
  for (const [reason, group] of counts) table.rows.push([String(directory), String(module),
    ["Unknown", "Not selected", "Not referenced"][reason] ?? `Unknown (${reason})`, String(group.records),
    String(group.sourceLines), group.sourceLines ? String(group.first) : "—", group.sourceLines ? String(group.last) : "—"]);
};

export const buildLegacyCodeViewDiscardedStatistics = (info: PeLegacyCodeViewInfo): LegacyCodeViewTable[] => {
  const table: LegacyCodeViewTable = { key: "discardedSymbols", title: "Discarded records by reason",
    columns: ["Directory", "Module", "Reason", "Records", "With source line", "First source line", "Last source line"],
    rows: [] };
  info.directories.forEach((directory, index) => {
    for (const section of directory.subsections) if (section.data) {
      appendSection(section.data, table, index + 1, section.module);
    }
  });
  return table.rows.length ? [table] : [];
};
