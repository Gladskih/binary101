import assert from "node:assert/strict";
import { test } from "node:test";
import { collectPeChecksWithoutFindings } from "../../../../renderers/pe/checks-without-findings.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";
import { createReadyToRunRendererFixture } from "../../../helpers/ready-to-run-renderer-fixture.js";
import { sanitizerCoffDebug } from "../../../fixtures/sanitizer-metadata.js";
import { createReadyToRunCompositeFixture } from "../../../helpers/ready-to-run-composite-fixture.js";
import { createLegacyCodeViewInfo } from "../../../fixtures/pe-legacy-codeview-view.js";
import { createTd32Info } from "../../../fixtures/pe-td32-view.js";
import type { PeDebugDirectoryEntry } from "../../../../analyzers/pe/debug/directory.js";

const debugEntry = (type: number): PeDebugDirectoryEntry => ({ characteristics: 0,
  timeDateStamp: 0, majorVersion: 0, minorVersion: 0, type, typeName: "fixture",
  sizeOfData: 0, addressOfRawData: 0, pointerToRawData: 0 });

const assertOmitted = (pe: ReturnType<typeof createBasePe>, names: string[]): void => {
  const missing = new Set(collectPeChecksWithoutFindings(pe));
  for (const name of names) assert.equal(missing.has(name), false, name);
};

void test("lists PE searches once and leaves DWARF to the common renderer", () => {
  const pe = createBasePe();

  const checks = collectPeChecksWithoutFindings(pe);

  assert.equal(checks.length, 19);
  for (const name of checks) assert.ok(name.length > 0);
  assert.equal(checks.filter(name => name === "Go runtime metadata").length, 1);
  assert.equal(checks.some(name => name.includes("DWARF")), false);
});

void test("lists Go as not detected when no Go metadata was returned", () => {
  assert.ok(collectPeChecksWithoutFindings(createBasePe()).includes("Go runtime metadata"));
});

void test("preserves diagnostics and candidate evidence instead of calling them absent", () => {
  const pe = createBasePe();
  pe.dRuntime = { modules: [], warnings: ["Ambiguous table"] };
  pe.appHost = { locators: [], bindings: [], issues: ["Unreadable locator"] };
  pe.nativeAotCandidate = { status: "candidate", evidence: ["section hint"], note: "Unconfirmed" };
  pe.itaniumRtti = { types: [], warnings: ["Unreadable data"] };
  pe.msvcEh = { records: [], warnings: ["Incomplete metadata"] };
  pe.debug = { entry: null, warning: "Truncated debug information" };

  assertOmitted(pe, ["D runtime metadata", ".NET apphost", "NativeAOT",
    "Itanium C++ RTTI", "Microsoft-compatible exception handling"]);
  assert.ok(collectPeChecksWithoutFindings(pe).some(name => name === "CodeView debug information"));
});

void test("distinguishes an absent ReadyToRun header from a present one", () => {
  const pe = createBasePe();
  pe.readyToRun = { ...createReadyToRunRendererFixture(), status: "absent" };

  assert.ok(collectPeChecksWithoutFindings(pe).some(name => name === "ReadyToRun"));
  pe.readyToRun = createReadyToRunRendererFixture();
  assertOmitted(pe, ["ReadyToRun"]);
});

void test("retains missing debug formats independently of other debug metadata", () => {
  const pe = createBasePe();
  pe.debug = { entry: null, entries: [] };
  pe.coffDebug = sanitizerCoffDebug();

  const names = collectPeChecksWithoutFindings(pe);
  assert.ok(names.includes("CodeView debug information"));
  assert.ok(names.includes("TD32 debug information"));
  assertOmitted(pe, ["COFF debug information"]);
});

void test("does not call validated archives or resource images absent", () => {
  const pe = createBasePe();
  pe.payloads = { entries: [
    { format: "pe", start: 0, end: 1, provenance: { location: "resource", discovery: "resource-leaf",
      validation: "pe-signatures", resourcePath: [] } },
    { format: "rar", start: 0, end: 1, provenance: { location: "overlay", discovery: "archive-scan",
      association: "unattributed", validation: "rar-end-archive" } },
    { format: "sevenzip", start: 0, end: 1, provenance: { location: "overlay", discovery: "archive-scan",
      association: "unattributed", validation: "sevenzip-next-header" } }
  ] };

  assertOmitted(pe, ["PE images in resources", "RAR archives in overlay", "7z archives in overlay"]);
});

void test("recognizes each standalone debug format and a TYPELIB independently", () => {
  const pe = createBasePe();
  pe.debug = { entry: null, codeViewSources: [{ kind: "section", offset: 0, size: 1,
    legacyCodeView: createLegacyCodeViewInfo() }],
  td32Sources: [{ kind: "section", offset: 0, size: 1, td32: createTd32Info() }] };
  pe.resources = { top: [], detail: [{ typeName: "TYPELIB", entries: [] }] };
  pe.clr = createReadyToRunCompositeFixture().clr;
  pe.clr.readyToRun = createReadyToRunRendererFixture();

  assertOmitted(pe, ["CodeView debug information", "TD32 debug information",
    "COM type-library resources", "ReadyToRun", "CLR header"]);
});

void test("distinguishes mixed debug-directory formats from standalone symbols", () => {
  const pe = createBasePe();
  pe.debug = { entry: null, entries: [
    { ...debugEntry(2), legacyCodeView: createLegacyCodeViewInfo() },
    { ...debugEntry(9), td32: createTd32Info() },
    { ...debugEntry(1), coff: sanitizerCoffDebug() }
  ] };

  assertOmitted(pe, ["CodeView debug information", "TD32 debug information", "COFF debug information"]);
});

void test("a COFF-only debug directory does not hide undetected CodeView or TD32", () => {
  const pe = createBasePe();
  pe.debug = { entry: null, entries: [{ ...debugEntry(1), coff: sanitizerCoffDebug() }] };

  const names = collectPeChecksWithoutFindings(pe);

  assert.ok(names.includes("CodeView debug information"));
  assert.ok(names.includes("TD32 debug information"));
  assertOmitted(pe, ["COFF debug information"]);
});

void test("a RAR payload does not hide undetected resource images or 7z archives", () => {
  const pe = createBasePe();
  pe.payloads = { entries: [{ format: "rar", start: 0, end: 1,
    provenance: { location: "overlay", discovery: "archive-scan", association: "unattributed",
      validation: "rar-end-archive" } }] };

  assertOmitted(pe, ["RAR archives in overlay"]);
  assert.ok(collectPeChecksWithoutFindings(pe).includes("7z archives in overlay"));
  assert.ok(collectPeChecksWithoutFindings(pe).includes("PE images in resources"));
});

void test("recognizes TYPELIB among other resource types", () => {
  const pe = createBasePe();
  pe.resources = { top: [], detail: [{ typeName: "RCDATA", entries: [] }] };
  assert.ok(collectPeChecksWithoutFindings(pe).includes("COM type-library resources"));

  pe.resources.detail.push({ typeName: "TYPELIB", entries: [] });

  assertOmitted(pe, ["COM type-library resources"]);
});

void test("does not report a Projector candidate or SWF payload as undetected", () => {
  const pe = createBasePe();
  pe.payloads = { entries: [], projectorCandidate: { start: 0, end: 1,
    swf: { signature: "CWS", version: 9, fileLength: 1, issues: [] } } };
  assertOmitted(pe, ["Flash Projector"]);

  pe.payloads = { entries: [{ start: 0, end: 1, format: "swf", provenance: { location: "overlay",
    discovery: "projector-footer", association: "flash-projector", validation: "projector-footer" },
    swf: { signature: "FWS", version: 9, fileLength: 1, tags: [], issues: [] } }] };

  assertOmitted(pe, ["Flash Projector"]);
});
