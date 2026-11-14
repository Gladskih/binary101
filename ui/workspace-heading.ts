import type { WorkspaceSection } from "./workspace-sections.js";

const hideHeading = (root: Document, section: WorkspaceSection | undefined, selected: string): boolean => {
  if (["hashes", "search"].includes(selected)) return false;
  return section?.title === "Preview" ||
    root.getElementById("inspectionWorkspace")!.classList.contains("workspaceContinuous");
};

export const renderWorkspaceHeading = (
  root: Document, section: WorkspaceSection | undefined, selected: string
): void => {
  root.getElementById("workspaceTitle")!.textContent = section?.title ??
    (selected === "search" ? "Search results" : selected === "hashes" ? "File hashes" : "Analysis");
  root.getElementById("workspaceDescription")!.textContent = section?.description ?? "";
  const heading = root.getElementById("workspaceHeading")!;
  heading.hidden = hideHeading(root, section, selected);
  if (section?.origin === "supplemental") {
    heading.dataset["analysisOrigin"] = "supplemental";
    heading.title = "Supplemental analysis";
  } else {
    delete heading.dataset["analysisOrigin"];
    heading.removeAttribute("title");
  }
};
