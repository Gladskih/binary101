"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  appendRelativeDirectoryPath,
  createDirectoryInspectionRoute,
  createRootDirectoryLocation
} from "../../../../ui/directory-inspection-route.js";
import type { BrowserDirectoryHandle } from "../../../../ui/directory-handles.js";

const createDirectoryHandle = (name: string): BrowserDirectoryHandle => ({
  kind: "directory",
  name,
  async *entries() {}
});

void test("directory routes copy locations and preserve root-relative paths", () => {
  const location = { handle: createDirectoryHandle("root"), name: "root", relativePath: "" };
  const route = createDirectoryInspectionRoute({ source: "selection", object: "directory" }, [location]);
  assert.notEqual(route.locations[0], location);
  assert.deepEqual(route.locations[0], location);
  assert.equal(appendRelativeDirectoryPath("", "docs"), "docs");
  assert.equal(appendRelativeDirectoryPath("docs", "readme.txt"), "docs/readme.txt");
  assert.equal(
    createRootDirectoryLocation(location.handle, route.context).relativePath,
    "root"
  );
  assert.equal(
    createRootDirectoryLocation(location.handle, { source: "drop", object: "collection" }).relativePath,
    ""
  );
});
