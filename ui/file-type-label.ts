"use strict";

import { isPeWindowsParseResult, type PeParseResult } from "../analyzers/pe/index.js";
import type { ParseForUiResult } from "../analyzers/index.js";
import { peSubtypeLabel } from "../analyzers/pe/subtype-labels.js";

type TooltipAdder = (element: HTMLElement, message: string) => void;

const hasPortableExecutableLabel = (typeLabel: string): boolean =>
  typeLabel.startsWith("PE") || typeLabel.includes("(PE") || typeLabel.includes(" PE ");

const refinePeBinaryTypeLabel = (typeLabel: string, pe: PeParseResult): string => {
  if (!isPeWindowsParseResult(pe) || !pe.subtype) return typeLabel;
  return `${peSubtypeLabel(pe.subtype)} (${typeLabel})`;
};

const refineFileBinaryTypeLabel = (typeLabel: string, result: ParseForUiResult): string =>
  result.analyzer === "pe" && result.parsed
    ? refinePeBinaryTypeLabel(typeLabel, result.parsed)
    : typeLabel;

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

export { refineFileBinaryTypeLabel, setFileBinaryTypeLabel };
