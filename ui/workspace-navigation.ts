import type { WorkspaceSection } from "./workspace-sections.js";

const navigationButton = (
  key: string,
  title: string,
  detail: string,
  origin?: WorkspaceSection["origin"]
): HTMLButtonElement => {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "workspaceNavItem";
  button.dataset["workspaceTarget"] = key;
  if (origin) {
    button.dataset["analysisOrigin"] = origin;
    button.title = "Supplemental analysis";
  }
  const label = document.createElement("span");
  label.textContent = title;
  button.append(label);
  if (detail) {
    const hint = document.createElement("span");
    hint.className = "workspaceNavItem__detail";
    hint.textContent = detail;
    button.append(hint);
  }
  return button;
};

export const renderWorkspaceSelect = (
  select: HTMLSelectElement,
  sections: WorkspaceSection[]
): void => {
  select.replaceChildren(
    new Option("Overview", "overview"),
    new Option("File hashes", "hashes"),
    ...sections.map(section => new Option(section.title, section.key))
  );
};

export const renderWorkspaceNavigation = (
  navigation: HTMLElement,
  sections: WorkspaceSection[]
): void => {
  navigation.replaceChildren(
    navigationButton("overview", "Overview", ""),
    navigationButton("hashes", "File hashes", "8 algorithms", "supplemental"),
    ...sections.map(section =>
      navigationButton(section.key, section.title, section.description, section.origin))
  );
};

export const filterWorkspaceNavigation = (navigation: HTMLElement, query: string): number => {
  let count = 0;
  navigation.querySelectorAll<HTMLElement>("[data-workspace-target]").forEach(button => {
    button.hidden = !button.textContent?.toLowerCase().includes(query.trim().toLowerCase());
    if (!button.hidden) count += 1;
  });
  return count;
};
