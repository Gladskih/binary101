"use strict";

type DetailsStateNode = {
  children?: Iterable<DetailsStateNode>;
  closest?(selector: string): DetailsStateNode | null;
  open?: boolean;
  parentElement?: DetailsStateNode | null;
  querySelectorAll?(selector: string): Iterable<DetailsStateNode>;
  tagName?: string;
  textContent?: string | null;
};

const normalizeDetailsLabel = (text: string | null | undefined): string =>
  text?.replace(/\s+/g, " ").trim() || "(untitled)";

const isDetailsNode = (
  node: DetailsStateNode | null | undefined
): node is DetailsStateNode => node?.tagName === "DETAILS";

const getDetailsSummaryText = (details: DetailsStateNode): string => {
  const summary = Array.from(details.children ?? []).find(child => child.tagName === "SUMMARY");
  return normalizeDetailsLabel(summary?.textContent);
};

const getDetailsStateKey = (details: DetailsStateNode): string => {
  const path: string[] = [];
  let current: DetailsStateNode | null = details;
  while (current) {
    path.unshift(getDetailsSummaryText(current));
    const parentDetails: DetailsStateNode | null = current.parentElement?.closest?.("details") ?? null;
    current = isDetailsNode(parentDetails) ? parentDetails : null;
  }
  return path.join(" > ");
};

export const captureOpenDetails = (root: DetailsStateNode): Set<string> => {
  const openDetails = new Set<string>();
  for (const details of Array.from(root.querySelectorAll?.("details") ?? [])) {
    if (details.open) openDetails.add(getDetailsStateKey(details));
  }
  return openDetails;
};

export const restoreOpenDetails = (
  root: DetailsStateNode,
  openDetails: Set<string>,
  syncViewer: (viewer: DetailsStateNode) => void
): void => {
  for (const details of Array.from(root.querySelectorAll?.("details") ?? [])) {
    details.open = openDetails.has(getDetailsStateKey(details));
  }
  for (const viewer of Array.from(root.querySelectorAll?.("[data-manifest-tree-viewer]") ?? [])) {
    syncViewer(viewer);
  }
};
