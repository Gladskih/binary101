import { reportTextPattern } from "./report-text-search.js";

export const findReportSectionMatch = (
  title: string, labels: readonly string[], query: string
): string | null => {
  const pattern = reportTextPattern(query);
  return pattern ? [title, ...labels].find(label => pattern.test(label)) ?? null : null;
};
