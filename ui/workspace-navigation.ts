import type { WorkspaceSection } from "./workspace-sections.js";
import type { ParseForUiResult } from "../analyzers/analyzer-types.js";
import { renderPeSectionPreview } from "../renderers/pe/section-preview.js";
import { renderOverviewCard } from "../renderers/overview-card.js";

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
  return renderOverviewCard(section.title, section.key, preview, section.origin);
}).join("");
