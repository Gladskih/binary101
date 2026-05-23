"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderDebug } from "../../renderers/pe/debug-view.js";
import {
  createSyntheticWarning,
  createDebugViewCodeView,
  createPeWithDebugViewSection,
  createRepeatedPogoDebugViewSection,
  createInconsistentEmbeddedDebugViewSection,
  createSupportedDebugViewSection,
  createDecodedDebugViewSection,
  createDebugViewEntry,
  createMappedCodeViewDebugViewSection,
  createUnresolvedDebugViewSection
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

const escapeRegExp = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const countMatches = (html: string, pattern: RegExp): number => [...html.matchAll(pattern)].length;

void test("renderDebug renders CodeView summary and plain entry values", () => {
  const pe = createPeWithDebugViewSection();
  const section = pe.sections[0]!;
  const codeView = createDebugViewCodeView();
  const warning = createSyntheticWarning();
  pe.debug = createMappedCodeViewDebugViewSection(section, codeView, warning);

  const html = renderDebugHtml(pe);

  assertIncludesAll(html, [
    "Debug directory",
    "IMAGE_DEBUG_DIRECTORY is an index of debug payloads",
    "Entry #1: CODEVIEW \\(MAPPED\\)",
    "Type",
    "What it contains",
    "Signature",
    "GUID",
      "Age",
      "Path",
      "Storage",
      "Raw RVA",
      "Raw file ptr",
      "CODEVIEW",
    "MAPPED",
    "CodeView RSDS record with PDB identity and path",
    "RSDS",
      escapeRegExp(codeView.path),
      escapeRegExp(warning)
  ]);
  assert.doesNotMatch(html, /Show debug directory entries/);
  assert.doesNotMatch(html, /Types present/);
  assert.doesNotMatch(html, /<span class="opt sel"[^>]*>CODEVIEW<\/span>/);
  assert.doesNotMatch(html, /<span class="opt sel"[^>]*>MAPPED<\/span>/);
  assert.doesNotMatch(html, /<dt[^>]*>CodeView<\/dt><dd>RSDS<\/dd>/);
});

void test("renderDebug keeps repeated types in the table instead of a counted summary", () => {
  const pe = createBasePe();
  pe.debug = createRepeatedPogoDebugViewSection();

  const html = renderDebugHtml(pe);

  assert.equal(countMatches(html, />POGO<div class="valueHint">/g), 2);
  assert.equal(countMatches(html, />UNMAPPED</g), 2);
  assert.doesNotMatch(html, /POGO x2/);
  assert.doesNotMatch(html, /UNMAPPED x2/);
  assert.doesNotMatch(html, /TYPE_13/);
});

void test("renderDebug marks contradictory RVA and section coverage as inconsistent", () => {
  const pe = createPeWithDebugViewSection();
  pe.debug = createInconsistentEmbeddedDebugViewSection(pe.sections[0]!);

  const html = renderDebugHtml(pe);

  assert.match(html, />EMBEDDED DEBUG<div class="valueHint">/);
  assert.match(html, />INCONSISTENT</);
  assert.doesNotMatch(html, /<span class="opt sel"[^>]*>EMBEDDED DEBUG<\/span>/);
});

void test("renderDebug renders supported debug-format labels and descriptions", () => {
  const pe = createBasePe();
  pe.debug = createSupportedDebugViewSection();

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
  pe.debug = createUnresolvedDebugViewSection();

  const html = renderDebugHtml(pe);

  assert.match(html, />TYPE_255<div class="valueHint">0x000000ff<\/div>/);
  assert.match(html, />UNRESOLVED</);
  assert.match(html, /Undocumented or unsupported IMAGE_DEBUG_DIRECTORY\.Type 0x000000ff\./);
});

void test("renderDebug renders decoded VC_FEATURE and POGO payload details", () => {
  const pe = createBasePe();
  const { pogo, debug } = createDecodedDebugViewSection();
  pe.debug = debug;

  const html = renderDebugHtml(pe);

  assertIncludesAll(html, [
    "Entry #1: VC_FEATURE \\(UNMAPPED\\)",
    "MSVC toolchain counters such as /GS, /sdl, and guardN",
    "Pre-VC\\+\\+ 11\\.00",
    "C/C\\+\\+",
    "guardN",
    "Entry #2: POGO \\(UNMAPPED\\)",
    "The table above stays as a compact index",
    "POGO records describe linker chunks used by profile-guided optimization",
    `${pogo.signatureName} \\(${escapeRegExp(`0x${pogo.signature.toString(16).padStart(8, "0")}`)}\\)`,
    String(pogo.entries.length),
    "Start RVA",
    escapeRegExp(pogo.entries[0]!.name),
    escapeRegExp(pogo.entries[1]!.name)
  ]);
  assert.doesNotMatch(html, /Types present/);
});

void test("renderDebug renders decoded details for extra debug payload formats", () => {
  const pe = createBasePe();
  pe.debug = {
    entry: null,
    entries: [
      {
        ...createDebugViewEntry(2, 0, 0x80, 26),
        codeView: { signature: "NB10", offset: 0, timestamp: 0x3aef6cec, age: 1, path: "crtdll.pdb" }
      },
      { ...createDebugViewEntry(3, 0, 0x90, 16), fpo: { records: [{
        startOffset: 0x1000,
        procedureSize: 0x20,
        localDwordCount: 2,
        parameterDwordCount: 3,
        prologByteCount: 0x12,
        savedRegisterCount: 5,
        hasStructuredExceptionHandling: true,
        usesBasePointer: true,
        frameType: 2
      }] } },
      {
        ...createDebugViewEntry(4, 0, 0xa0, 26),
        misc: { dataType: 1, length: 26, unicode: false, text: "mfc40_opt.DBG" }
      },
      { ...createDebugViewEntry(16, 0, 0xb0, 0), repro: { hashLength: null, hashBytes: [] } },
      {
        ...createDebugViewEntry(17, 0, 0xc0, 9),
        embeddedPortablePdb: { signature: "MPDB", uncompressedSize: 115724, compressedSize: 91953 }
      },
      {
        ...createDebugViewEntry(19, 0, 0xd0, 9),
        pdbChecksum: { algorithmName: "SHA256", checksumBytes: [0xaa, 0xbb] }
      },
      { ...createDebugViewEntry(20, 0, 0xe0, 4), exDllCharacteristics: { value: 0x41 } },
      { ...createDebugViewEntry(10, 0, 0xf0, 4), rawPayload: { previewBytes: [0xb4, 0x9c] } }
    ],
    rawDataRanges: []
  };

  const html = renderDebugHtml(pe);

  assertIncludesAll(html, [
    "CodeView NB10 record with PDB identity and path",
    "crtdll\\.pdb",
    "Frame-pointer omission table with 1 records",
    "mfc40_opt\\.DBG",
    "Deterministic build marker",
    "MPDB",
    "SHA256",
    "0x00000041",
    "b4 9c"
  ]);
});
