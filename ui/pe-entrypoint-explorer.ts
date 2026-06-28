"use strict";

import type { ParseForUiResult } from "../analyzers/index.js";
import { isPeWindowsParseResult, type PeWindowsParseResult } from "../analyzers/pe/index.js";
import {
  DEFAULT_PE_ENTRYPOINT_EXPLORER_STATE,
  moveEntrypointExplorerPage,
  normalizeEntrypointExplorerState,
  renderEntrypointExplorerContent,
  selectEntrypointBlock,
  selectEntrypointRva,
  visibleEntrypointBlocks,
  type PeEntrypointExplorerState,
  type PeEntrypointRenderBlock
} from "../renderers/pe/entrypoint-disassembly-explorer.js";

type PeEntrypointExplorerRuntime = {
  blocks: PeEntrypointRenderBlock[];
  state: PeEntrypointExplorerState;
};

const ROOT_SELECTOR = "[data-pe-entrypoint-explorer]";
const runtimeByElement = new WeakMap<HTMLElement, PeEntrypointExplorerRuntime>();

export const enhancePeEntrypointExplorer = (
  root: ParentNode,
  pe: PeWindowsParseResult
): void => {
  if (!pe.entrypointDisassembly) return;
  const blocks = visibleEntrypointBlocks(pe.entrypointDisassembly.blocks);
  for (const element of explorerElements(root)) {
    const runtime = {
      blocks,
      state: normalizeEntrypointExplorerState(blocks, readState(element))
    };
    runtimeByElement.set(element, runtime);
    renderRuntime(element, runtime);
    element.addEventListener("click", event => handleClick(element, event));
    element.addEventListener("change", event => handleChange(element, event));
  }
};

export const enhanceAnalysisEntrypointExplorer = (
  root: ParentNode,
  result: ParseForUiResult
): void => {
  if (result.analyzer !== "pe" || !result.parsed || !isPeWindowsParseResult(result.parsed)) return;
  enhancePeEntrypointExplorer(root, result.parsed);
};

export const selectPeEntrypointRva = (root: ParentNode, rva: number): boolean => {
  if (!Number.isSafeInteger(rva) || rva < 0) return false;
  for (const element of explorerElements(root)) {
    const runtime = runtimeByElement.get(element);
    if (!runtime) continue;
    const state = selectEntrypointRva(runtime.blocks, rva);
    if (!state) continue;
    runtime.state = state;
    renderRuntime(element, runtime);
    return true;
  }
  return false;
};

const handleClick = (element: HTMLElement, event: Event): void => {
  const target = event.target instanceof Element ? event.target : null;
  const selector = target?.closest<HTMLElement>("[data-pe-entrypoint-block-select]");
  if (selector) {
    event.preventDefault();
    selectBlock(element, selector);
    return;
  }
  const pager = target?.closest<HTMLElement>("[data-pe-entrypoint-page-action]");
  if (!pager) return;
  event.preventDefault();
  movePage(element, pager);
};

const handleChange = (element: HTMLElement, event: Event): void => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement)) return;
  const pageTarget = readPageTarget(target.dataset["peEntrypointPageInput"] ?? "");
  if (!pageTarget) return;
  const runtime = runtimeByElement.get(element);
  if (!runtime) return;
  runtime.state = moveEntrypointExplorerPage(
    runtime.blocks,
    runtime.state,
    pageTarget,
    Number(target.value) - 1
  );
  renderRuntime(element, runtime);
};

const selectBlock = (element: HTMLElement, selector: HTMLElement): void => {
  const runtime = runtimeByElement.get(element);
  const blockIndex = Number(selector.dataset["peEntrypointBlockSelect"]);
  if (!runtime || !Number.isInteger(blockIndex)) return;
  runtime.state = selectEntrypointBlock(runtime.blocks, blockIndex);
  renderRuntime(element, runtime);
};

const movePage = (element: HTMLElement, pager: HTMLElement): void => {
  const runtime = runtimeByElement.get(element);
  const pageTarget = readPageTarget(pager.dataset["peEntrypointPageTarget"] ?? "");
  const action = readPageAction(pager.dataset["peEntrypointPageAction"] ?? "");
  if (!runtime || !pageTarget || !action) return;
  runtime.state = moveEntrypointExplorerPage(runtime.blocks, runtime.state, pageTarget, action);
  renderRuntime(element, runtime);
};

const renderRuntime = (
  element: HTMLElement,
  runtime: PeEntrypointExplorerRuntime
): void => {
  runtime.state = normalizeEntrypointExplorerState(runtime.blocks, runtime.state);
  element.dataset["peEntrypointSelectedBlockIndex"] = String(runtime.state.selectedBlockIndex);
  element.dataset["peEntrypointBlockPageIndex"] = String(runtime.state.blockPageIndex);
  element.dataset["peEntrypointInstructionPageIndex"] = String(runtime.state.instructionPageIndex);
  element.innerHTML = renderEntrypointExplorerContent(runtime.blocks, runtime.state);
};

const readState = (element: HTMLElement): PeEntrypointExplorerState => ({
  selectedBlockIndex: readInteger(element.dataset["peEntrypointSelectedBlockIndex"]),
  blockPageIndex: readInteger(element.dataset["peEntrypointBlockPageIndex"]),
  instructionPageIndex: readInteger(element.dataset["peEntrypointInstructionPageIndex"])
});

const readInteger = (value: string | undefined): number => {
  const parsed = Number(value);
  return Number.isInteger(parsed) ? parsed : 0;
};

const readPageTarget = (value: string): "blocks" | "instructions" | null =>
  value === "blocks" || value === "instructions" ? value : null;

const readPageAction = (
  value: string
): "first" | "previous" | "next" | "last" | null =>
  value === "first" || value === "previous" || value === "next" || value === "last"
    ? value
    : null;

const explorerElements = (root: ParentNode): HTMLElement[] => {
  const out: HTMLElement[] = [];
  if (root instanceof HTMLElement && root.matches(ROOT_SELECTOR)) out.push(root);
  const queryRoot = root as ParentNode & {
    querySelectorAll?: (selector: string) => Iterable<unknown>;
  };
  if (typeof queryRoot.querySelectorAll !== "function") return out;
  for (const element of queryRoot.querySelectorAll(ROOT_SELECTOR)) {
    if (element instanceof HTMLElement) out.push(element);
  }
  return out;
};

export { DEFAULT_PE_ENTRYPOINT_EXPLORER_STATE };
