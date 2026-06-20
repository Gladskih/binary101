"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { setFileBinaryTypeLabel } from "../../../ui/file-type-label.js";

void test("file type labels add PE help only for PE formats", () => {
  const element = { textContent: "" } as unknown as HTMLElement;
  const messages: string[] = [];
  setFileBinaryTypeLabel(element, "Text file", (_, message) => { messages.push(message); });
  assert.equal(element.textContent, "Text file");
  assert.equal(messages.length, 0);
  setFileBinaryTypeLabel(element, "PE32 executable", (_, message) => { messages.push(message); });
  assert.equal(messages.length, 1);
  assert.match(messages[0] ?? "", /Portable Executable/);
});
