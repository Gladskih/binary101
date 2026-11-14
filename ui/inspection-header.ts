// At 960px, the 256px navigation and 320px details pane leave 384px for the report.
export const WIDE_INSPECTION_QUERY = "(min-width: 960px) and (min-height: 560px)";

const moveElement = (child: HTMLElement, parent: HTMLElement): void => {
  if (child.parentElement !== parent) parent.append(child);
};

const syncContext = (root: Document, appTitle: string): void => {
  const fileVisible = !root.getElementById("fileInfoCard")!.hidden;
  const directoryVisible = !root.getElementById("directoryInfoCard")!.hidden;
  root.body.classList.toggle("hasInspection", fileVisible || directoryVisible);
  const name = fileVisible ? root.getElementById("fileNameDetail")!.textContent :
    directoryVisible ? root.getElementById("directoryName")!.textContent : null;
  root.title = name ? `${name} — ${appTitle}` : appTitle;
};

export const syncInspectionHeader = (
  root: Document, appTitle: string, layout: Pick<MediaQueryList, "matches">
): void => {
  const element = (id: string): HTMLElement => root.getElementById(id)!;
  const fileVisible = !element("fileInfoCard").hidden;
  const details = element("fileDetails") as HTMLDetailsElement;
  details.hidden = !fileVisible;
  moveElement(details, element(fileVisible && !layout.matches ? "fileActions" : "fileInfoRail"));
  const docked = fileVisible && layout.matches;
  const headerParent = element(docked ? "fileChromeDock" : "appHeader");
  moveElement(element("fileHeader"), headerParent);
  moveElement(element("fileActions"), headerParent);
  moveElement(element("workspaceSearch"), element(docked ? "fileChromeDock" : "workspaceSearchHome"));
  moveElement(element("fileIconWrap"), element(docked ? "fileInfoRail" : "fileDetailsBody"));
  root.body.classList.toggle("hasDockedHeader", docked);
  syncContext(root, appTitle);
};
