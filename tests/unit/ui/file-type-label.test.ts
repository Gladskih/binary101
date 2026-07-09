"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  refineFileBinaryTypeLabel,
  setFileBinaryTypeLabel
} from "../../../ui/file-type-label.js";
import type { ParseForUiResult } from "../../../analyzers/index.js";

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

void test("file type labels refine parsed PE subtypes", () => {
  const baseLabel = "PE32 DLL for x86 (I386)";
  const result = {
    analyzer: "pe",
    parsed: {
      // Microsoft PE/COFF: 0x10b identifies PE32 optional headers.
      opt: { Magic: 0x10b },
      subtype: "winmd",
      dirs: []
    }
  } as unknown as ParseForUiResult;

  assert.equal(
    refineFileBinaryTypeLabel(baseLabel, result),
    "Windows Metadata (WinMD) (PE32 DLL for x86 (I386))"
  );
});

void test("file type labels add PE help for refined PE subtype labels", () => {
  const element = { textContent: "" } as unknown as HTMLElement;
  const messages: string[] = [];

  setFileBinaryTypeLabel(
    element,
    ".NET reference assembly (metadata-only) (PE32 DLL for x86 (I386))",
    (_, message) => { messages.push(message); }
  );

  assert.equal(messages.length, 1);
  assert.match(messages[0] ?? "", /Portable Executable/);
});
