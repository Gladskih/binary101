import type { HllSource } from "../../analyzers/pe/debug/hll-source.js";

export const hllSourceRows = (data: HllSource): string[][] => {
  const names = new Map(data.files.map(file => [file.index, file.name]));
  const summaries = new Map<string, { file: number; category: string; segments: Set<number>;
    count: number; values: Set<number> }>();
  const referenced = new Set<number>();
  for (const group of data.groups) {
    const key = `${group.file}:${group.category}`;
    const summary = summaries.get(key) ?? { file: group.file, category: group.category,
      segments: new Set<number>(), count: 0, values: new Set<number>() };
    summary.segments.add(group.segment);
    summary.count += group.values.length;
    for (const value of group.values) summary.values.add(value);
    referenced.add(group.file);
    summaries.set(key, summary);
  }
  const rows = [...summaries.values()].map(summary => [names.get(summary.file) ??
    (summary.file === 0 ? "Unspecified file" : `Unknown file #${summary.file}`),
  summary.category, String(summary.segments.size), String(summary.count), String(summary.values.size)]);
  for (const file of data.files) if (!referenced.has(file.index)) rows.push([file.name, "Source file", "0", "0", "0"]);
  return rows;
};
