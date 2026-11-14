import type { WorkspaceSection } from "./workspace-sections.js";
import type { ParseForUiResult } from "../analyzers/analyzer-types.js";

const fallbackSection = (
  sections: readonly Pick<WorkspaceSection, "key" | "title" | "origin">[]
): string => sections.find(section => section.title === "Preview")?.key ??
  sections.find(section => !section.origin)?.key ?? sections[0]?.key ?? "hashes";

export const initialWorkspaceSection = (
  sections: readonly Pick<WorkspaceSection, "key" | "title" | "origin">[],
  analyzer: ParseForUiResult["analyzer"] | undefined
): string => {
  if (analyzer === "pe") {
    return sections.find(section => section.key === "analysis-pe-headers")?.key ?? fallbackSection(sections);
  }
  if (analyzer === "elf") {
    return sections.find(section => section.key === "analysis-header")?.key ?? fallbackSection(sections);
  }
  return fallbackSection(sections);
};
