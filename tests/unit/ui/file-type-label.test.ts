"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  setFileBinaryTypeLabel,
  setFileSubtypeLabel
} from "../../../ui/file-type-label.js";
import type { ParseForUiResult } from "../../../analyzers/index.js";

void test("file type labels add PE help only for PE formats", () => {
  const element = { textContent: "" } as unknown as HTMLElement;
  const messages: string[] = [];
  setFileBinaryTypeLabel(element, "Text file", (_, message) => { messages.push(message); });
  assert.equal(element.textContent, "Text file");
  assert.equal(messages.length, 0);
  setFileBinaryTypeLabel(
    element,
    "PEM armor block (certificate/key text encoding)",
    (_, message) => { messages.push(message); }
  );
  assert.equal(messages.length, 0);
  setFileBinaryTypeLabel(element, "PE32 executable", (_, message) => { messages.push(message); });
  assert.equal(messages.length, 1);
  assert.match(messages[0] ?? "", /Portable Executable/);
});

void test("file type labels show parsed PE subtypes separately", () => {
  const termElement = { hidden: true } as HTMLElement;
  const detailElement = { hidden: true, textContent: "" } as HTMLElement;
  const result = {
    analyzer: "pe",
    parsed: {
      // Microsoft PE/COFF: 0x10b identifies PE32 optional headers.
      opt: { Magic: 0x10b },
      subtype: "winmd",
      dirs: []
    }
  } as unknown as ParseForUiResult;

  setFileSubtypeLabel(termElement, detailElement, result);

  assert.equal(termElement.hidden, false);
  assert.equal(detailElement.hidden, false);
  assert.equal(detailElement.textContent, "Windows Metadata (WinMD)");
});

void test("file type labels hide subtype rows without a parsed subtype", () => {
  const termElement = { hidden: false } as HTMLElement;
  const detailElement = { hidden: false, textContent: "Windows Metadata (WinMD)" } as HTMLElement;

  setFileSubtypeLabel(
    termElement,
    detailElement,
    { analyzer: "pe", parsed: { dirs: [] } } as unknown as ParseForUiResult
  );

  assert.equal(termElement.hidden, true);
  assert.equal(detailElement.hidden, true);
  assert.equal(detailElement.textContent, "");
});
