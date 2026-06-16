"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { captureOpenDetails, restoreOpenDetails } from "../../../ui/details-open-state.js";

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
  parentDetails: DetailsStateNode | null,
  ignoreState = false
): DetailsStateNode => ({
  tagName: "DETAILS",
  open,
  parentElement: createContainer(parentDetails),
  children: [createSummary(summaryText)],
  closest: (selector: string) => selector === '[data-details-open-state="ignore"]' && ignoreState
    ? ({} as DetailsStateNode)
    : null
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

void test("captureOpenDetails and restoreOpenDetails ignore opted-out details", () => {
  const outer = createDetails("MANIFEST", true, null);
  const xmlSource = createDetails("XML source", true, outer, true);
  const root: DetailsStateNode = {
    querySelectorAll: (selector: string) => selector === "details" ? [outer, xmlSource] : []
  };
  const captured = captureOpenDetails(root);
  outer.open = false;
  xmlSource.open = false;

  restoreOpenDetails(root, captured, () => undefined);

  assert.equal(outer.open, true);
  assert.equal(xmlSource.open, false);
  assert.equal(captured.has("MANIFEST > XML source"), false);
});
