"use strict";

type SectionEntropyState = {
  entropy?: number | null;
};

export const SECTION_ENTROPY_TOOLTIP =
  "Shannon entropy (0..8 bits/byte). High values can indicate compressed, encrypted, or " +
  "packed data; entropy alone is not a packer verdict.";

export const formatSectionEntropy = (entropy: number | null | undefined): string =>
  entropy === undefined
    ? "Not calculated"
    : typeof entropy === "number" && Number.isFinite(entropy)
      ? entropy.toFixed(2)
      : "Unavailable";

export const sectionEntropySortValue = (entropy: number | null | undefined): string =>
  typeof entropy === "number" && Number.isFinite(entropy) ? String(entropy) : "";

export const renderSectionEntropyValue = (
  entropy: number | null | undefined,
  sectionIndex: number
): string => {
  const className = typeof entropy === "number" && Number.isFinite(entropy)
    ? ""
    : ` class="dim"`;
  return `<span data-section-entropy-index="${sectionIndex}"${className}>` +
    `${formatSectionEntropy(entropy)}</span>`;
};

export const sectionEntropySummary = (sections: readonly SectionEntropyState[]): string => {
  const available = sections.filter(section =>
    typeof section.entropy === "number" && Number.isFinite(section.entropy)
  ).length;
  const unavailable = sections.length - available;
  return `Calculated for ${available} of ${sections.length} sections` +
    (unavailable
      ? `; ${unavailable} raw range${unavailable === 1 ? "" : "s"} unavailable.`
      : ".");
};

export const renderSectionEntropyControl = (
  sections: readonly SectionEntropyState[]
): string => {
  const calculated = sections.every(section => section.entropy !== undefined);
  const label = calculated
    ? "Recalculate entropy for all sections"
    : "Calculate entropy for all sections";
  const status = calculated
    ? sectionEntropySummary(sections)
    : "Reads every complete raw section range on demand.";
  return `<div style="margin:.35rem 0 .5rem 0">` +
    `<button type="button" class="tableButton" data-section-entropy-action>${label}</button> ` +
    `<span class="smallNote dim" data-section-entropy-status>${status}</span></div>`;
};
