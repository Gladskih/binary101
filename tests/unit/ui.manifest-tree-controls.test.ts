"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  handleManifestTreeActionClick,
  syncManifestTreeControls
} from "../../ui/manifest-tree-controls.js";

const createButton = (action: "expand" | "collapse", viewer: unknown) => ({
  dataset: { manifestTreeAction: action },
  disabled: false,
  closest: (selector: string) => (selector === "[data-manifest-tree-viewer]" ? viewer : null)
});

const createFixture = (action: "expand" | "collapse") => {
  const details = [{ open: true }, { open: false }, { open: true }];
  const viewer = {
    closest: () => null,
    querySelectorAll: (selector: string) => {
      if (selector === "details") return details;
      if (selector === '[data-manifest-tree-action="expand"]') return [expandButton];
      if (selector === '[data-manifest-tree-action="collapse"]') return [collapseButton];
      return [];
    }
  };
  const expandButton = createButton("expand", viewer);
  const collapseButton = createButton("collapse", viewer);
  const actionButton = action === "expand" ? expandButton : collapseButton;
  const target = {
    closest: (selector: string) => (selector === "[data-manifest-tree-action]" ? actionButton : null)
  };
  return { collapseButton, details, expandButton, target };
};

void test("handleManifestTreeActionClick expands all manifest tree nodes and updates button state", () => {
  const fixture = createFixture("expand");

  assert.equal(handleManifestTreeActionClick(fixture.target as never), true);
  assert.deepEqual(fixture.details.map(node => node.open), [true, true, true]);
  assert.equal(fixture.expandButton.disabled, true);
  assert.equal(fixture.collapseButton.disabled, false);
});

void test("handleManifestTreeActionClick collapses all manifest tree nodes and updates button state", () => {
  const fixture = createFixture("collapse");
  fixture.details.forEach(node => {
    node.open = true;
  });

  assert.equal(handleManifestTreeActionClick(fixture.target as never), true);
  assert.deepEqual(fixture.details.map(node => node.open), [false, false, false]);
  assert.equal(fixture.expandButton.disabled, false);
  assert.equal(fixture.collapseButton.disabled, true);
});

void test("syncManifestTreeControls disables the action that cannot change the tree", () => {
  const fixture = createFixture("expand");

  syncManifestTreeControls(fixture.expandButton as never);
  assert.equal(fixture.expandButton.disabled, false);
  assert.equal(fixture.collapseButton.disabled, false);

  fixture.details.forEach(node => {
    node.open = false;
  });
  syncManifestTreeControls(fixture.expandButton as never);
  assert.equal(fixture.expandButton.disabled, false);
  assert.equal(fixture.collapseButton.disabled, true);
});

void test("handleManifestTreeActionClick ignores unrelated clicks", () => {
  const target = { closest: () => null };
  assert.equal(handleManifestTreeActionClick(target as never), false);
});
