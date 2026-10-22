import type { PeLegacyCodeViewInfo, LegacyCodeViewData } from "../../analyzers/pe/debug/legacy-codeview.js";
import type { LegacyCodeViewIndex } from "../../analyzers/pe/debug/legacy-codeview-index.js";
import type { LegacyCodeViewTable } from "./legacy-codeview-tables.js";
import { legacyCodeViewSubsectionName } from "./legacy-codeview-kinds.js";

const NAME_ALGORITHMS = new Map([[0, "No index"], [2, "Byte sum"],
  [6, "Shifted byte sum"], [10, "XOR/rotate DWORD checksum"]]);
const ADDRESS_ALGORITHMS = new Map([[0, "No index"], [4, "Section sort"], [5, "Aligned section sort"],
  [8, "Modified section sort"], [12, "Grouped section sort"]]);

const logicalSectionNames = (contents: readonly (LegacyCodeViewData | undefined)[]): Map<number, string> => {
  const names = new Map<number, string>();
  let segments: Extract<LegacyCodeViewData, { kind: "segmentMap" }> | undefined;
  for (const data of contents) {
    if (data?.kind === "segmentNames") for (const value of data.names) names.set(value.offset, value.name);
    if (data?.kind === "segmentMap") segments = data;
  }
  return new Map(segments?.segments.map((segment, index) => [index + 1, names.get(segment.name) ?? ""]));
};

const summaryRow = (index: LegacyCodeViewIndex, algorithms: ReadonlyMap<number, string>): string[] => {
  const algorithm = algorithms.get(index.algorithm) ?? `Unsupported algorithm ${index.algorithm}`;
  if (!index.counts) return [algorithm, "—", "—", "—", "—"];
  return [algorithm, String(index.counts.length), String(index.counts.filter(count => count > 0).length),
    String(index.counts.reduce((total, count) => total + count, 0)),
    String(index.counts.reduce((largest, count) => Math.max(largest, count), 0))];
};

const occupancyRows = (counts: readonly number[]): string[][] => {
  const frequencies = new Map<number, number>();
  for (const count of counts) frequencies.set(count, (frequencies.get(count) ?? 0) + 1);
  return [...frequencies].sort(([left], [right]) => left - right)
    .map(([count, buckets]) => [String(count), String(buckets)]);
};

const sectionRows = (counts: readonly number[], names: ReadonlyMap<number, string>): string[][] =>
  counts.flatMap((count, index) => count || names.get(index + 1)
    ? [[names.get(index + 1) || `#${index + 1}`, String(count)]] : []);

const appendNameIndex = (summary: LegacyCodeViewTable, buckets: LegacyCodeViewTable,
  index: LegacyCodeViewIndex | undefined, prefix: string[]): void => {
  if (!index) return;
  summary.rows.push([...prefix, "Names", ...summaryRow(index, NAME_ALGORITHMS)]);
  for (const row of occupancyRows(index.counts ?? [])) buckets.rows.push([...prefix, ...row]);
};

const appendAddressIndex = (summary: LegacyCodeViewTable, sections: LegacyCodeViewTable,
  index: LegacyCodeViewIndex | undefined, prefix: string[], names: ReadonlyMap<number, string>): void => {
  if (!index) return;
  summary.rows.push([...prefix, "Addresses", ...summaryRow(index, ADDRESS_ALGORITHMS)]);
  for (const row of sectionRows(index.counts ?? [], names)) sections.rows.push([...prefix, ...row]);
};

export const buildLegacyCodeViewIndexTables = (info: PeLegacyCodeViewInfo): LegacyCodeViewTable[] => {
  const summary: LegacyCodeViewTable = { key: "indexes", title: "Symbol index statistics (declared counts)",
    columns: ["Directory", "Module", "Subsection", "Index kind", "Algorithm", "Groups", "Nonempty groups",
      "References", "Largest group"], rows: [] };
  const buckets: LegacyCodeViewTable = { key: "buckets", title: "Name hash bucket occupancy",
    columns: ["Directory", "Module", "Subsection", "References per bucket", "Buckets"], rows: [] };
  const sections: LegacyCodeViewTable = { key: "indexedSections", title: "Indexed symbols by logical section",
    columns: ["Directory", "Module", "Subsection", "Section", "References"], rows: [] };
  info.directories.forEach((directory, directoryIndex) => {
    const names = logicalSectionNames(directory.subsections.map(section => section.data));
    for (const section of directory.subsections) {
      if (section.data?.kind !== "symbols") continue;
      const prefix = [String(directoryIndex + 1), String(section.module), legacyCodeViewSubsectionName(section.type)];
      appendNameIndex(summary, buckets, section.data.nameIndex, prefix);
      appendAddressIndex(summary, sections, section.data.addressIndex, prefix, names);
    }
  });
  return [summary, buckets, sections].filter(table => table.rows.length > 0);
};
