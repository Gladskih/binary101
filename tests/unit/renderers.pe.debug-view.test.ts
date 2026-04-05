"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderDebug } from "../../renderers/pe/debug-view.js";
import {
  createDebugViewCodeView,
  createRepeatedDebugViewSection,
  createSectionCoveredRawOnlyDebugViewEntry,
  createDebugViewSection,
  createMappedDebugViewEntry,
  createPeWithDebugViewSection,
  createSequentialDebugViewSection,
  createDebugViewEntry
} from "../fixtures/pe-debug-view-subject.js";
import { createBasePe } from "../fixtures/pe-renderer-headers-fixture.js";

const renderDebugHtml = (pe: ReturnType<typeof createBasePe>): string => {
  const out: string[] = [];
  renderDebug(pe, out);
  return out.join("");
};

const assertIncludesAll = (html: string, snippets: string[]): void => {
  snippets.forEach(snippet => assert.match(html, new RegExp(snippet)));
};

const countMatches = (html: string, pattern: RegExp): number => [...html.matchAll(pattern)].length;

void test("renderDebug renders CodeView summary and plain entry values", () => {
  const pe = createPeWithDebugViewSection();
  const section = pe.sections[0]!;
  const codeView = createDebugViewCodeView(1);
  pe.debug = createDebugViewSection([{
    ...createMappedDebugViewEntry(section, 2, 0),
    codeView
  }], codeView, "fixture-warning");

  const html = renderDebugHtml(pe);

  assertIncludesAll(html, [
    "Debug directory",
    "Storage column shows whether the payload is mapped into the image",
    "CodeView",
    "GUID",
    "Age",
    "Path",
    "Storage",
    "Show debug directory entries \\(1\\)",
    "Raw RVA",
    "Raw file ptr",
    "CODEVIEW",
    "MAPPED",
    "RSDS fixture-1\\.pdb",
    "fixture-1\\.pdb",
    "fixture-warning"
  ]);
  assert.doesNotMatch(html, /Types present/);
  assert.doesNotMatch(html, /<span class="opt sel"[^>]*>CODEVIEW<\/span>/);
  assert.doesNotMatch(html, /<span class="opt sel"[^>]*>MAPPED<\/span>/);
});

void test("renderDebug keeps repeated types in the table instead of a counted summary", () => {
  const pe = createBasePe();
  pe.debug = createRepeatedDebugViewSection(13, 2);

  const html = renderDebugHtml(pe);

  assert.equal(countMatches(html, />POGO<div class="valueHint">/g), 2);
  assert.equal(countMatches(html, />UNMAPPED</g), 2);
  assert.doesNotMatch(html, /POGO x2/);
  assert.doesNotMatch(html, /UNMAPPED x2/);
  assert.doesNotMatch(html, /TYPE_13/);
});

void test("renderDebug marks contradictory RVA and section coverage as inconsistent", () => {
  const pe = createPeWithDebugViewSection();
  pe.debug = createDebugViewSection([
    createSectionCoveredRawOnlyDebugViewEntry(pe.sections[0]!, 17, 0)
  ]);

  const html = renderDebugHtml(pe);

  assert.match(html, />EMBEDDED DEBUG<div class="valueHint">/);
  assert.match(html, />INCONSISTENT</);
  assert.doesNotMatch(html, /<span class="opt sel"[^>]*>EMBEDDED DEBUG<\/span>/);
});

void test("renderDebug renders supported debug-format labels and descriptions", () => {
  const pe = createBasePe();
  const supportedTypes = [0, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 19, 20];
  pe.debug = createSequentialDebugViewSection(supportedTypes);

  const html = renderDebugHtml(pe);

  assertIncludesAll(html, [
    "UNKNOWN",
    "COFF",
    "FPO",
    "MISC",
    "EXCEPTION",
    "FIXUP",
    "OMAP_TO_SRC",
    "OMAP_FROM_SRC",
    "BORLAND",
    "RESERVED10",
    "CLSID",
    "VC_FEATURE",
    "POGO",
    "ILTCG",
    "MPX",
    "REPRO",
    "SYMBOL HASH",
    "EX_DLLCHARACTERISTICS"
  ]);
  assertIncludesAll(html, [
    "Unknown debug format ignored by tools\\.",
    "COFF line numbers, symbol table, and string table\\.",
    "Frame-pointer omission metadata for nonstandard stack frames\\.",
    "Legacy location of a DBG file\\.",
    "Copy of the \\.pdata exception data\\.",
    "Reserved FIXUP debug type\\.",
    "Reserved IMAGE_DEBUG_TYPE_RESERVED10 debug type\\.",
    "Reserved CLSID debug type\\.",
    "Visual C\\+\\+ feature metadata emitted by the toolchain\\.",
    "Profile-guided optimization metadata emitted by the linker\\.",
    "Link-time code generation metadata emitted by the toolchain\\.",
    "Intel MPX metadata emitted by the toolchain\\.",
    "PE determinism or reproducibility metadata\\.",
    "Crypto hash of the symbol file content used to build the PE/COFF file\\.",
    "Extended DLL characteristics bits beyond the optional-header field\\."
  ]);
  assert.doesNotMatch(html, /<span class="opt sel"/);
});

void test("renderDebug shows fallback types and unresolved storage when payload location is missing", () => {
  const pe = createBasePe();
  pe.debug = createDebugViewSection([createDebugViewEntry(255, 0, 0, 0)]);

  const html = renderDebugHtml(pe);

  assert.match(html, />TYPE_255<div class="valueHint">0x000000ff<\/div>/);
  assert.match(html, />UNRESOLVED</);
  assert.match(html, /Undocumented or unsupported IMAGE_DEBUG_DIRECTORY\.Type 0x000000ff\./);
});
