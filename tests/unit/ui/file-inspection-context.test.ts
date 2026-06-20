"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileInspectionContext } from "../../../ui/file-inspection-context.js";

const createElementMap = (): Map<string, { hidden: boolean; innerHTML: string; textContent: string }> => new Map([
  ["fileObjectDetail", { hidden: false, innerHTML: "", textContent: "" }],
  ["fileRelativePathDetail", { hidden: false, innerHTML: "", textContent: "" }],
  ["fileRelativePathTerm", { hidden: false, innerHTML: "", textContent: "" }],
  ["fileSourceDetail", { hidden: false, innerHTML: "", textContent: "" }]
]);

void test("file inspection context renders and clears file context", () => {
  const elements = createElementMap();
  const context = createFileInspectionContext(id => elements.get(id) as unknown as HTMLElement);
  context.render({ source: "navigation", object: "file", relativePath: "docs/readme.txt" });
  assert.match(elements.get("fileSourceDetail")?.innerHTML ?? "", />Navigation<\/span>/);
  assert.match(elements.get("fileObjectDetail")?.innerHTML ?? "", />File<\/span>/);
  assert.equal(elements.get("fileRelativePathDetail")?.textContent, "docs/readme.txt");
  context.clear();
  assert.equal(elements.get("fileSourceDetail")?.innerHTML, "");
  assert.equal(elements.get("fileRelativePathTerm")?.hidden, true);
});
