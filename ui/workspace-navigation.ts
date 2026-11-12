import type { WorkspaceSection } from "./workspace-sections.js";
import type { ParseForUiResult } from "../analyzers/analyzer-types.js";
import { escapeHtmlText } from "../html-utils.js";
import { renderPeSectionPreview } from "../renderers/pe/section-preview.js";

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

export const renderWorkspaceCards = (
  sections: readonly Pick<WorkspaceSection, "key" | "title" | "description" | "origin">[],
  result: ParseForUiResult | null
): string => [...sections.filter(section => !section.origin),
  ...sections.filter(section => section.origin)].map(section => {
  const preview = result?.analyzer === "pe" ? renderPeSectionPreview(result.parsed,
    section.key.replace(/^analysis-/, "")) : "";
  // The DOS summary repeats e_lfanew, already present in the native-field preview.
  const description = preview && section.key === "analysis-dos-header" ? "" : section.description;
  return `<article class="workspaceCard"` +
    (section.origin ? ` data-analysis-origin="${section.origin}" title="Supplemental analysis"` : "") + `>` +
    `<h4><button type="button" class="overviewLink" ` +
    `data-workspace-target="${escapeHtmlText(section.key)}">${escapeHtmlText(section.title)}</button></h4>` +
    (description ? `<p>${escapeHtmlText(description)}</p>` : "") + preview + `</article>`;
}).join("");
