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
  sections: WorkspaceSection[],
  query = ""
): void => {
  select.replaceChildren(new Option("File hashes", "overview"));
  if (query.trim()) select.append(new Option("Search results", "search"));
  for (const [label, items] of [
    ["File structure", sections.filter(section => !section.origin)],
    ["Analysis", sections.filter(section => section.origin)]
  ] as const) {
    if (!items.length) continue;
    const group = document.createElement("optgroup");
    group.label = label;
    group.append(...items.map(section => new Option(section.title, section.key)));
    select.append(group);
  }
};

export const renderWorkspaceNavigation = (
  navigation: HTMLElement,
  sections: WorkspaceSection[]
): void => {
  const buttons = (items: WorkspaceSection[]) => items.map(section =>
    navigationButton(section.key, section.title, section.description, section.origin));
  navigation.replaceChildren(...buttons(sections.filter(section => !section.origin)));
  if (!sections.some(section => section.origin)) return;
  const analysis = document.createElement("div");
  analysis.className = "workspaceAnalysis";
  analysis.setAttribute("role", "group");
  analysis.setAttribute("aria-label", "Supplemental analysis");
  analysis.append(...buttons(sections.filter(section => section.origin)));
  navigation.append(analysis);
};

export const filterWorkspaceNavigation = (navigation: HTMLElement, query: string): number => {
  let count = 0;
  navigation.querySelectorAll<HTMLElement>("[data-workspace-target]").forEach(button => {
    button.hidden = !button.textContent?.toLowerCase().includes(query.trim().toLowerCase());
    if (!button.hidden) count += 1;
  });
  return count;
};
