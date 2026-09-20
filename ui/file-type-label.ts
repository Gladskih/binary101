"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";
import type { ElfParseResult } from "../analyzers/elf/types.js";
import { peSubtypeLabel } from "../analyzers/pe/subtype-labels.js";

type TooltipAdder = (element: HTMLElement, message: string) => void;

const hasPortableExecutableLabel = (typeLabel: string): boolean =>
  /^PE(?:32|\b)/.test(typeLabel);

function fileSubtypeLabel(result: ParseForUiResult): string | null {
  if (result.analyzer === "elf") return elfSubtypeLabel(result.parsed);
  return result.analyzer === "pe" && result.parsed?.subtype
    ? peSubtypeLabel(result.parsed.subtype)
    : null;
}

const setFileBinaryTypeLabel = (
  element: HTMLElement,
  typeLabel: string,
  addTooltip: TooltipAdder
): void => {
  element.textContent = typeLabel;
  if (!hasPortableExecutableLabel(typeLabel)) return;
  addTooltip(
    element,
    "Portable Executable (PE) / COFF is the executable and object-file format used by " +
    "Windows toolchains."
  );
};

const setFileSubtypeLabel = (
  termElement: HTMLElement,
  detailElement: HTMLElement,
  result: ParseForUiResult
): void => {
  const label = fileSubtypeLabel(result);
  termElement.hidden = label == null;
  detailElement.hidden = label == null;
  detailElement.textContent = label ?? "";
};

export { setFileBinaryTypeLabel, setFileSubtypeLabel };

function elfSubtypeLabel(elf: ElfParseResult | null): string | null {
  // DF_1_PIE: https://github.com/bminor/glibc/blob/master/elf/elf.h
  if (elf?.header.type === 3 &&
    ((elf.dynamic?.flags1 ?? 0) & 0x08000000) !== 0) {
    return "Position-independent executable (PIE)";
  }
  return null;
}
