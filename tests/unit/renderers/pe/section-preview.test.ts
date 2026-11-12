import assert from "node:assert/strict";
import { test } from "node:test";
import { renderPeSectionPreview } from "../../../../renderers/pe/section-preview.js";
import { createBasePe, createPeSection } from "../../../fixtures/pe-renderer-headers-fixture.js";
import { readOverviewFacts } from "../../../helpers/overview-card-fixture.js";
import { parseForUi } from "../../../../analyzers/index.js";
import { createPeRomFile } from "../../../fixtures/sample-files-pe.js";
import type { PeImportEntry } from "../../../../analyzers/pe/imports/index.js";

const moduleEntry = (dll: string, count: number): PeImportEntry => ({ dll, originalFirstThunkRva: 0,
  firstThunkRva: 0, timeDateStamp: 0, forwarderChain: 0,
  functions: Array.from({ length: count }, (_, index) => ({ name: `Symbol${index}` })),
  lookupSource: "missing", thunkTableTerminated: false });

void test("import highlights select the actual maximum and totals without dumping function names", () => {
  const pe = createBasePe();
  pe.imports.entries = [moduleEntry("first.dll", 1), moduleEntry("<largest>.dll", 4), moduleEntry("third.dll", 2)];

  const html = renderPeSectionPreview(pe, "imports");

  assert.deepEqual(readOverviewFacts(html), [["DLL with most imports", "<largest>.dll"],
    ["Imports from this DLL", "4"], ["Total imports", "7 from 3 DLLs"]]);
  assert.doesNotMatch(html, /Symbol|<table|<ul|first.dll|third.dll/);
  assert.equal(pe.imports.entries[0]!.dll, "first.dll");
  assert.equal(pe.imports.entries[1]!.functions.length, 4);
  assert.equal(renderPeSectionPreview(pe, "unknown"), "");
  assert.equal(renderPeSectionPreview(pe, "resources"), "");
});

void test("empty names, a single DLL and tied maxima keep their factual meaning", () => {
  const pe = createBasePe();
  pe.imports.entries = [moduleEntry("", 1)];

  assert.deepEqual(readOverviewFacts(renderPeSectionPreview(pe, "imports")), [
    ["DLL with most imports", "(empty DLL name)"], ["Imports from this DLL", "1"],
    ["Total imports", "1 from 1 DLL"]]);
  pe.imports.entries.push(moduleEntry("tie.dll", 1));
  assert.equal(readOverviewFacts(renderPeSectionPreview(pe, "imports"))[0]![1], "(empty DLL name)");
});

void test("section highlights compare raw and virtual sizes independently", () => {
  const pe = createBasePe();
  pe.sections = [createPeSection(".virtual", { sizeOfRawData: 1, virtualSize: 3000 }),
    createPeSection("<raw>", { sizeOfRawData: 1024, virtualSize: 2 }),
    createPeSection(".bss", { sizeOfRawData: 0, virtualSize: 5000 }),
    createPeSection(".small", { sizeOfRawData: 0, virtualSize: 1 })];

  assert.deepEqual(readOverviewFacts(renderPeSectionPreview(pe, "section-headers")), [
    ["Largest SizeOfRawData", "<raw> · 1 KB (1024 bytes)"],
    ["Largest VirtualSize", ".bss · 4.9 KB (5000 bytes)"]]);
});

void test("directory highlights count nonzero entries without claiming they are valid ranges", () => {
  const pe = createBasePe();
  pe.dirs = [{ name: "empty", rva: 0, size: 0 }, { name: "rva only", rva: 1, size: 0 },
    { name: "<largest>", rva: 0, size: 1024 }, { name: "small", rva: 1, size: 1 }];

  assert.deepEqual(readOverviewFacts(renderPeSectionPreview(pe, "data-directories")), [
    ["Largest directory", "<largest>"], ["Size", "1 KB (1024 bytes)"], ["Nonzero directory entries", "3"]]);
});

void test("export highlights count every alias and forwarder", () => {
  const pe = createBasePe();
  pe.exports = { flags: 0, timestamp: 0, version: 0, dllName: "library.dll", Base: 1,
    NumberOfFunctions: 2, NumberOfNames: 3, namePointerTable: 0, ordinalTable: 0, issues: [],
    entries: [{ ordinal: 1, rva: 1, names: ["a", "b"], forwarder: "target.fn" },
      { ordinal: 2, rva: 2, names: [] }] };

  assert.deepEqual(readOverviewFacts(renderPeSectionPreview(pe, "exports")), [
    ["DLL name", "library.dll"], ["Named exports", "2"], ["Forwarded exports", "1"]]);
  pe.exports.dllName = "";
  assert.equal(readOverviewFacts(renderPeSectionPreview(pe, "exports"))[0]![1], "(empty DLL name)");
  pe.exports.entries = [];
  assert.equal(renderPeSectionPreview(pe, "exports"), "");
});

void test("signature highlights preserve mixed checks without inventing a file verdict", () => {
  const pe = createBasePe();
  pe.security = { count: 1, certs: [{ offset: 0, length: 8, availableBytes: 8, revision: 0x200,
    revisionName: "2.0", certificateType: 2, typeName: "PKCS#7",
    authenticode: { format: "pkcs7", verification: { checks: [
      { id: "file-digest-match", title: "Digest", status: "pass" },
      { id: "certificate", title: "Certificate", status: "fail" },
      { id: "trust", title: "Trust", status: "unknown" }
    ] } } }] };

  const html = renderPeSectionPreview(pe, "security");

  assert.deepEqual(readOverviewFacts(html), [["Embedded file digest", "pass"],
    ["Recorded checks", "1 pass · 1 fail · 1 unknown"], ["WIN_CERTIFICATE records", "1"]]);
  assert.doesNotMatch(html, /safe|trusted file|<table|<ul/);
  delete pe.security.certs[0]!.authenticode;
  assert.equal(readOverviewFacts(renderPeSectionPreview(pe, "security"))[0]![1], "Not reported");
  pe.security.certs[0]!.authenticode = { format: "pkcs7" };
  assert.equal(readOverviewFacts(renderPeSectionPreview(pe, "security"))[0]![1], "Not reported");
});

void test("multiple signature records preserve conflicting digest results", () => {
  const pe = createBasePe();
  const record = { offset: 0, length: 8, availableBytes: 8, revision: 0x200,
    revisionName: "2.0", certificateType: 2, typeName: "PKCS#7" };
  pe.security = { count: 2, certs: ["pass", "fail"].map(status => ({ ...record,
    authenticode: { format: "pkcs7", verification: { checks: [{ id: "file-digest-match", title: "Digest",
      status: status === "pass" ? "pass" : "fail" }] } } })) };

  assert.equal(readOverviewFacts(renderPeSectionPreview(pe, "security"))[0]![1], "pass · fail");
});

void test("absent collections, unknown destinations and ROM structures produce no empty tiles", async () => {
  const pe = createBasePe();
  pe.sections = [];
  pe.dirs = [];
  const rom = await parseForUi(createPeRomFile());
  assert.equal(rom.analyzer, "pe");

  for (const key of ["imports", "exports", "security", "resources", "section-headers", "data-directories", "unknown"]) {
    assert.equal(renderPeSectionPreview(pe, key), "");
  }
  for (const key of ["imports", "exports", "security", "resources", "unknown"]) {
    assert.equal(renderPeSectionPreview(rom.parsed, key), "");
  }
  assert.match(renderPeSectionPreview(rom.parsed, "section-headers"), /Largest SizeOfRawData/);
  assert.match(renderPeSectionPreview(pe, "pe-headers"), /Machine/);
});
