"use strict";

import { hex } from "../../binary-utils.js";
import type { PeEntrypointRenderBlock } from "./entrypoint-disassembly-model.js";
import { renderEntrypointJumpButton } from "./entrypoint-disassembly-links.js";

const SOURCE_PREVIEW_LIMIT = 3;

export const renderEntrypointBlockKind = (block: PeEntrypointRenderBlock): string => {
  if (block.block.kind === "entrypoint") return "Entry point";
  if (block.block.kind === "followed-call") return "Call target";
  if (block.block.kind === "followed-jump") return "Jump target";
  if (block.block.kind === "followed-import-return") return "Import return";
  if (block.block.kind === "followed-return") return "Return target";
  return block.block.kind === "followed-branch" ? "Branch target" : "Branch fallthrough";
};

export const renderEntrypointBlockLabel = (block: PeEntrypointRenderBlock): string => {
  const source = sourceLabel(block);
  const duplicates = duplicateLabel(block);
  if (block.block.kind === "entrypoint") return `Entry point${duplicates}`;
  if (block.block.kind === "followed-call") return `Followed call target${source}${duplicates}`;
  if (block.block.kind === "followed-jump") return `Followed jump target${source}${duplicates}`;
  if (block.block.kind === "followed-import-return") {
    return `Followed returning import fallthrough${source}${duplicates}`;
  }
  if (block.block.kind === "followed-return") return `Followed return target${source}${duplicates}`;
  return block.block.kind === "followed-branch"
    ? `Followed conditional branch target${source}${duplicates}`
    : `Followed conditional fallthrough${source}${duplicates}`;
};

export const renderEntrypointSourcesPreview = (block: PeEntrypointRenderBlock): string => {
  if (!block.sources.length) return `<span class="dim">-</span>`;
  const sources = block.sources.slice(0, SOURCE_PREVIEW_LIMIT).map(renderEntrypointJumpButton);
  const hiddenCount = block.sources.length - sources.length;
  const suffix = hiddenCount > 0 ? ` <span class="dim">+${hiddenCount} more</span>` : "";
  return `${sources.join(", ")}${suffix}`;
};

export const renderEntrypointSourceLinks = (sources: readonly number[]): string =>
  sources.length
    ? sources.map(renderEntrypointJumpButton).join(", ")
    : `<span class="dim">-</span>`;

const sourceLabel = (block: PeEntrypointRenderBlock): string => {
  if (!block.sources.length) return "";
  if (block.sources.length <= SOURCE_PREVIEW_LIMIT) {
    return ` from ${block.sources.map(rva => hex(rva, 8)).join(", ")}`;
  }
  return ` from ${block.sources.length} source(s)`;
};

const duplicateLabel = (block: PeEntrypointRenderBlock): string =>
  block.duplicateCount > 1 ? `; ${block.duplicateCount - 1} duplicate context(s) merged` : "";
