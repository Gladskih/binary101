"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { captureOpenDetails, restoreOpenDetails } from "../../ui/details-open-state.js";

type DetailsStateNode = Parameters<typeof restoreOpenDetails>[0];

const createSummary = (text: string): DetailsStateNode => ({
  tagName: "SUMMARY",
  textContent: text
});

const createContainer = (parentDetails: DetailsStateNode | null): DetailsStateNode => ({
  closest: (selector: string) => (selector === "details" ? parentDetails : null)
});

const createDetails = (
  summaryText: string,
  open: boolean,
  parentDetails: DetailsStateNode | null
): DetailsStateNode => ({
  tagName: "DETAILS",
  open,
  parentElement: createContainer(parentDetails),
  children: [createSummary(summaryText)]
});

void test("captureOpenDetails and restoreOpenDetails preserve nested open states", () => {
  const outer = createDetails("PE/COFF headers", true, null);
  const inner = createDetails("Section headers", false, outer);
  const viewer = { tagName: "DIV" };
  const root: DetailsStateNode = {
    querySelectorAll: (selector: string) => {
      if (selector === "details") return [outer, inner];
      if (selector === "[data-manifest-tree-viewer]") return [viewer];
      return [];
    }
  };
  const syncedViewers: DetailsStateNode[] = [];

  const captured = captureOpenDetails(root);
  outer.open = false;
  inner.open = true;

  restoreOpenDetails(root, captured, viewerNode => {
    syncedViewers.push(viewerNode);
  });

  assert.equal(outer.open, true);
  assert.equal(inner.open, false);
  assert.deepEqual(syncedViewers, [viewer]);
});
