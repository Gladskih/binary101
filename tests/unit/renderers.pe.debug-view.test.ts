"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { PeDebugDirectoryEntry } from "../../analyzers/pe/debug-directory.js";
import { renderDebug } from "../../renderers/pe/debug-view.js";
import {
  createBasePe,
  createPeSection
} from "../fixtures/pe-renderer-headers-fixture.js";

const createDebugEntry = (
  type: number,
  addressOfRawData: number,
  pointerToRawData: number,
  sizeOfData = 0x20
): PeDebugDirectoryEntry => ({
  type,
  typeName: `TYPE_${type}`,
  sizeOfData,
  addressOfRawData,
  pointerToRawData
});

const createCodeViewEntry = (path: string) => ({
  guid: "04030201-0605-0807-090a-0b0c0d0e0f10",
  age: 7,
  path
});

const createPeWithMappedDebugSection = () => {
  const pe = createBasePe();
  pe.sections = [
    createPeSection(".rdata", {
      virtualAddress: 0x1000,
      pointerToRawData: 0x400,
      sizeOfRawData: 0x200
    })
  ];
  pe.coff.NumberOfSections = pe.sections.length;
  return pe;
};

const renderDebugHtml = (pe: ReturnType<typeof createBasePe>): string => {
  const out: string[] = [];
  renderDebug(pe, out);
  return out.join("");
};

const createSequentialDebugEntries = (types: number[]) => ({
  entries: types.map((type, index) => createDebugEntry(type, 0, 0x200 + index * 0x20)),
  rawDataRanges: types.map((_, index) => ({
    start: 0x200 + index * 0x20,
    end: 0x220 + index * 0x20
  }))
});

const assertChip = (html: string, label: string): void => {
  assert.match(html, new RegExp(`<span class="opt sel"[^>]*>${label}</span>`));
};

const assertChips = (html: string, labels: string[]): void => {
  labels.forEach(label => assertChip(html, label));
};

const assertIncludesAll = (html: string, snippets: string[]): void => {
  snippets.forEach(snippet => assert.match(html, new RegExp(snippet)));
};

void test("renderDebug renders CodeView summary, chip markup, and entry table", () => {
  const pe = createPeWithMappedDebugSection();
  pe.debug = {
    entry: createCodeViewEntry("C:\\symbols\\mapped.pdb"),
    entries: [{
      ...createDebugEntry(2, 0x1040, 0x440, 0x30),
      codeView: createCodeViewEntry("C:\\symbols\\mapped.pdb")
    }],
    rawDataRanges: [{ start: 0x440, end: 0x470 }],
    warning: "Debug directory parsed from IMAGE_DEBUG_DIRECTORY."
  };

  const html = renderDebugHtml(pe);

  assertChip(html, "CODEVIEW");
  assertChip(html, "MAPPED");
  assertIncludesAll(html, [
    "Debug directory",
    "storage chip shows whether the payload is mapped into the image",
    "CodeView",
    "GUID",
    "Age",
    "Path",
    "Directory entries",
    "Types present",
    "Storage",
    "Show debug directory entries \\(1\\)",
    "Raw RVA",
    "Raw file ptr",
    "RSDS C:\\\\symbols\\\\mapped\\.pdb",
    "mapped\\.pdb",
    "Debug directory parsed from IMAGE_DEBUG_DIRECTORY"
  ]);
});

void test("renderDebug renders counted chips for repeated linker metadata entries", () => {
  const pe = createBasePe();
  pe.debug = {
    entry: null,
    entries: [
      createDebugEntry(13, 0, 0x900),
      createDebugEntry(13, 0, 0x940)
    ],
    rawDataRanges: [
      { start: 0x900, end: 0x920 },
      { start: 0x940, end: 0x960 }
    ]
  };

  const html = renderDebugHtml(pe);

  assertChip(html, "POGO x2");
  assertChip(html, "UNMAPPED x2");
  assert.doesNotMatch(html, /TYPE_13/);
});

void test("renderDebug marks contradictory RVA and section coverage as inconsistent", () => {
  const pe = createPeWithMappedDebugSection();
  pe.debug = {
    entry: null,
    entries: [createDebugEntry(17, 0, 0x440)],
    rawDataRanges: [{ start: 0x440, end: 0x460 }]
  };

  const html = renderDebugHtml(pe);

  assertChip(html, "EMBEDDED DEBUG");
  assertChip(html, "INCONSISTENT");
});

void test("renderDebug renders supported debug-format labels and descriptions", () => {
  const pe = createBasePe();
  const supportedTypes = [0, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 19, 20];
  pe.debug = {
    entry: null,
    ...createSequentialDebugEntries(supportedTypes)
  };

  const html = renderDebugHtml(pe);

  assertChips(html, [
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
});

void test("renderDebug shows fallback types and unresolved storage when payload location is missing", () => {
  const pe = createBasePe();
  pe.debug = {
    entry: null,
    entries: [createDebugEntry(255, 0, 0, 0)],
    rawDataRanges: []
  };

  const html = renderDebugHtml(pe);

  assertChip(html, "TYPE_255");
  assertChip(html, "UNRESOLVED");
  assert.match(html, /Undocumented or unsupported IMAGE_DEBUG_DIRECTORY\.Type 0x000000ff\./);
});
