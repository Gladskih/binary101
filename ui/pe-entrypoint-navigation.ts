"use strict";

import { selectPeEntrypointRva } from "./pe-entrypoint-explorer.js";

const FLASH_CLASS = "peEntrypointTargetFlash";

const findJumpButton = (targetElement: Element | null): HTMLElement | null => {
  const button = targetElement?.closest("[data-pe-entrypoint-jump]");
  return button instanceof HTMLElement ? button : null;
};

const findJumpTarget = (root: ParentNode, rva: string): HTMLElement | null => {
  const row = root.querySelector(`[data-pe-entrypoint-rva="${rva}"].peEntrypointInstructionRow`);
  if (row instanceof HTMLElement) return row;
  const block = root.querySelector(`[data-pe-entrypoint-rva="${rva}"].peEntrypointBlock`);
  return block instanceof HTMLElement ? block : null;
};

export const handlePeEntrypointJumpClick = (
  targetElement: Element | null,
  root: ParentNode
): boolean => {
  const button = findJumpButton(targetElement);
  const rva = button?.dataset["peEntrypointJump"];
  if (!button || !rva) return false;
  const target = findJumpTarget(root, rva) ?? selectAndFindTarget(root, rva);
  if (!target) return true;
  target.classList.remove(FLASH_CLASS);
  void target.offsetWidth;
  target.classList.add(FLASH_CLASS);
  target.focus({ preventScroll: true });
  target.scrollIntoView({ block: "center", inline: "nearest" });
  return true;
};

const selectAndFindTarget = (root: ParentNode, rva: string): HTMLElement | null => {
  const parsed = Number(rva);
  if (!selectPeEntrypointRva(root, parsed)) return null;
  return findJumpTarget(root, rva);
};
