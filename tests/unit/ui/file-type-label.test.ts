"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  setFileBinaryTypeLabel,
  setFileSubtypeLabel
} from "../../../ui/file-type-label.js";
import type { ParseForUiResult } from "../../../analyzers/index.js";
import { relocationFixture } from "../../fixtures/elf-relocations.js";

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

void test("ELF subtypes distinguish PIE from unmarked shared objects", () => {
  const elf = relocationFixture().elf;
  elf.header.type = 3;
  const term = { hidden: true } as HTMLElement;
  const detail = { hidden: true, textContent: "" } as HTMLElement;
  setFileSubtypeLabel(term, detail, { analyzer: "elf", parsed: elf });
  assert.equal(term.hidden, true);
  // DF_1_PIE from glibc elf.h; ET_DYN alone cannot distinguish executables.
  elf.dynamic = { needed: [], flags1: 0x08000000, soname: null, rpath: null, runpath: null,
    init: null, fini: null, preinitArray: null, initArray: null, finiArray: null,
    flags: null, issues: [] };
  setFileSubtypeLabel(term, detail, { analyzer: "elf", parsed: elf });
  assert.equal(term.hidden, false);
  assert.equal(detail.textContent, "Position-independent executable (PIE)");
  elf.header.type = 2;
  setFileSubtypeLabel(term, detail, { analyzer: "elf", parsed: elf });
  assert.equal(term.hidden, true);
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

void test("file type labels describe parsed .NET apphost subtypes", () => {
  const termElement = { hidden: true } as HTMLElement;
  const detailElement = { hidden: true, textContent: "" } as HTMLElement;

  setFileSubtypeLabel(termElement, detailElement, {
    analyzer: "pe",
    parsed: { subtype: "dotnet-apphost", dirs: [] }
  } as unknown as ParseForUiResult);

  assert.equal(detailElement.textContent, ".NET apphost");
});
