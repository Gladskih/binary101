"use strict";

type ElementLike = {
  closest(selector: string): ElementLike | null;
  disabled?: boolean;
  dataset?: Record<string, string | undefined>;
  open?: boolean;
  querySelectorAll?(selector: string): Iterable<ElementLike>;
};

const getManifestTreeState = (viewer: ElementLike): { hasExpanded: boolean; hasCollapsed: boolean } => {
  const detailsNodes = viewer.querySelectorAll ? Array.from(viewer.querySelectorAll("details")) : [];
  return {
    hasExpanded: detailsNodes.some(details => !!details.open),
    hasCollapsed: detailsNodes.some(details => !details.open)
  };
};

const setButtonDisabled = (
  viewer: ElementLike,
  action: "expand" | "collapse",
  disabled: boolean
): void => {
  if (!viewer.querySelectorAll) return;
  for (const button of Array.from(viewer.querySelectorAll(`[data-manifest-tree-action="${action}"]`))) {
    button.disabled = disabled;
  }
};

export const syncManifestTreeControls = (targetElement: Element | null): void => {
  const viewer = (targetElement as ElementLike | null)?.closest("[data-manifest-tree-viewer]");
  if (!viewer) return;
  const state = getManifestTreeState(viewer);
  setButtonDisabled(viewer, "expand", !state.hasCollapsed);
  setButtonDisabled(viewer, "collapse", !state.hasExpanded);
};

export const handleManifestTreeActionClick = (targetElement: Element | null): boolean => {
  const actionButton = (targetElement as ElementLike | null)?.closest("[data-manifest-tree-action]");
  if (!actionButton) return false;
  if (actionButton.disabled) return true;
  const action = actionButton.dataset?.["manifestTreeAction"];
  const viewer = actionButton.closest("[data-manifest-tree-viewer]");
  if (!viewer?.querySelectorAll) return true;
  const detailsNodes = Array.from(viewer.querySelectorAll("details"));
  for (const details of detailsNodes) {
    details.open = action === "expand";
  }
  syncManifestTreeControls(actionButton as Element as Element | null);
  return true;
};
