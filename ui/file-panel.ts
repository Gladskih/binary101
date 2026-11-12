// Keep file actions outside the collapsible metadata and preserve the same search input.
export const attachFilePanelControls = (root: Document): void => {
  const rail = root.getElementById("fileInfoRail")!;
  const toggle = root.getElementById("filePanelToggle")!;
  const expand = (): void => {
    delete rail.dataset["collapsed"];
    toggle.setAttribute("aria-expanded", "true");
    toggle.setAttribute("aria-label", "Hide file panel");
    toggle.title = "Hide file panel";
  };
  toggle.addEventListener("click", () => {
    if (rail.dataset["collapsed"] === "true") { expand(); return; }
    rail.dataset["collapsed"] = "true";
    toggle.setAttribute("aria-expanded", "false");
    toggle.setAttribute("aria-label", "Show file panel");
    toggle.title = "Show file panel";
  });
  root.getElementById("filePanelSearch")!.addEventListener("click", () => {
    expand();
    root.getElementById("workspaceFilter")!.focus({ preventScroll: true });
  });
  expand();
};
