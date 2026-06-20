"use strict";

type TooltipAdder = (element: HTMLElement, message: string) => void;

const setFileBinaryTypeLabel = (
  element: HTMLElement,
  typeLabel: string,
  addTooltip: TooltipAdder
): void => {
  element.textContent = typeLabel;
  if (!typeLabel.startsWith("PE")) return;
  addTooltip(
    element,
    "Portable Executable (PE) / COFF is the executable and object-file format used by " +
    "Windows toolchains."
  );
};

export { setFileBinaryTypeLabel };
