"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";
import { calculateSectionEntropies } from "../analyzers/section-entropy.js";
import {
  formatSectionEntropy,
  sectionEntropySortValue,
  sectionEntropySummary
} from "../renderers/section-entropy.js";

type SectionEntropyDeps = {
  getParseResult: () => ParseForUiResult;
  getFile: () => File | null;
  setStatusMessage: (message: string | null | undefined) => void;
};

type EntropySection = {
  pointerToRawData: number;
  sizeOfRawData: number;
  entropy?: number | null;
};

const entropySections = (result: ParseForUiResult): EntropySection[] | null => {
  if (result.analyzer === "pe" || result.analyzer === "coff") return result.parsed.sections;
  return null;
};

const updateRenderedEntropies = (
  root: HTMLElement,
  sections: readonly EntropySection[]
): void => {
  root.querySelectorAll<HTMLElement>("[data-section-entropy-index]").forEach(element => {
    const sectionIndex = Number(element.getAttribute("data-section-entropy-index"));
    const entropy = Number.isInteger(sectionIndex) ? sections[sectionIndex]?.entropy : undefined;
    element.textContent = formatSectionEntropy(entropy);
    element.className = typeof entropy === "number" && Number.isFinite(entropy) ? "" : "dim";
    element.closest("td")?.setAttribute("data-sort-value", sectionEntropySortValue(entropy));
  });
  const status = root.querySelector<HTMLElement>("[data-section-entropy-status]");
  if (status) status.textContent = sectionEntropySummary(sections);
};

const setButtonBusy = (button: HTMLButtonElement): void => {
  button.disabled = true;
  button.textContent = "Calculating...";
};

export const createSectionEntropyClickHandler = (deps: SectionEntropyDeps) =>
  async (event: Event): Promise<void> => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest<HTMLButtonElement>("[data-section-entropy-action]");
    if (!button) return;
    const root = button.closest<HTMLElement>("[data-section-entropy-root]");
    const file = deps.getFile();
    const parseResult = deps.getParseResult();
    const sections = entropySections(parseResult);
    if (!root || !file || !sections?.length) {
      deps.setStatusMessage("Section entropy is not available.");
      return;
    }
    setButtonBusy(button);
    deps.setStatusMessage("Calculating section entropy...");
    try {
      const entropies = await calculateSectionEntropies(file, sections);
      if (deps.getFile() !== file || deps.getParseResult().parsed !== parseResult.parsed) return;
      sections.forEach((section, index) => { section.entropy = entropies[index] ?? null; });
      updateRenderedEntropies(root, sections);
      button.textContent = "Recalculate entropy for all sections";
      deps.setStatusMessage(null);
    } catch (error) {
      const message = error instanceof Error && error.message ? error.message : String(error);
      const status = root.querySelector<HTMLElement>("[data-section-entropy-status]");
      if (status) status.textContent = `Entropy calculation failed: ${message}`;
      button.textContent = "Retry entropy";
      deps.setStatusMessage(`Entropy calculation failed: ${message}`);
    } finally {
      button.disabled = false;
    }
  };
