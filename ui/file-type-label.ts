"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";
import { peSubtypeLabel } from "../analyzers/pe/subtype-labels.js";

type TooltipAdder = (element: HTMLElement, message: string) => void;

const hasPortableExecutableLabel = (typeLabel: string): boolean =>
  /^PE(?:32|\b)/.test(typeLabel);

const fileSubtypeLabel = (result: ParseForUiResult): string | null =>
  result.analyzer === "pe" && result.parsed?.subtype
    ? peSubtypeLabel(result.parsed.subtype)
    : null;

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
