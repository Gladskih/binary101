import assert from "node:assert/strict";
import { test } from "node:test";
import { renderNativeFileOverview } from "../../../renderers/native-file-overview.js";
import { createBasePe } from "../../fixtures/pe-renderer-headers-fixture.js";
import { parseForUi } from "../../../analyzers/index.js";
import { createElfMetadataFile } from "../../fixtures/elf-metadata-file.js";
import { createPeRomFile } from "../../fixtures/sample-files-pe.js";
import { createWebmFile } from "../../fixtures/webm-base-fixtures.js";
import { readOverviewDocument, readOverviewFacts } from "../../helpers/overview-card-fixture.js";

const language = (size: number) => ({ lang: null, size, codePage: 0, dataRVA: 0,
  dataFileOffset: null, reserved: 0 });

void test("resources highlight identification fields without reproducing VERSION tables", () => {
  const pe = createBasePe();
  pe.resources = { top: [], detail: [{ typeName: "VERSION", entries: [{ id: 1, name: null,
    langs: [{ ...language(100), versionInfo: { stringValues: [
      { table: "040904E4", key: "FileDescription", value: "<Product>" },
      { table: "040904E4", key: "FileVersion", value: "1.2.3" },
      { table: "040904E4", key: "CompanyName", value: "A&B" },
      { table: "040904E4", key: "InternalName", value: "Full detail only" }
    ] } }] }] }] };

  const html = renderNativeFileOverview({ analyzer: "pe", parsed: pe });

  assert.deepEqual(readOverviewFacts(html), [["FileDescription", "<Product>"],
    ["FileVersion", "1.2.3"], ["CompanyName", "A&B"]]);
  assert.match(html, /data-workspace-target="analysis-resources"/);
  assert.doesNotMatch(html, /Full detail only|<table|<ul|<ol|<details/);
});

void test("conflicting VERSION values are reported rather than choosing one locale as authoritative", () => {
  const pe = createBasePe();
  pe.resources = { top: [], detail: [{ typeName: "VERSION", entries: [{ id: null, name: "named",
    langs: [{ ...language(100), versionInfo: { stringValues: [
      { table: "one", key: "FileDescription", value: "One" },
      { table: "two", key: "FileDescription", value: "Two" },
      { table: "three", key: "FileDescription", value: "One" }
    ] } }] }] }] };

  assert.deepEqual(readOverviewFacts(renderNativeFileOverview({ analyzer: "pe", parsed: pe })),
    [["FileDescription", "2 distinct values"]]);
});

void test("resources select one representative icon and retain unknown source identifiers in its alt", () => {
  const pe = createBasePe();
  pe.resources = { top: [], issues: ["A warning"], detail: [
    { typeName: "PNG", entries: [{ id: 1, name: null, langs: [{ ...language(100),
      previewKind: "image", previewDataUrl: "data:image/png;base64,AA==" }] }] },
    { typeName: "ICON", entries: [{ id: null, name: "<icon>", langs: [
      { ...language(1), previewKind: "image", previewDataUrl: "data:image/png;base64,AQ==" },
      { ...language(20), previewKind: "image", previewDataUrl: "data:image/png;base64,Ag==" },
      { ...language(2), previewKind: "image", previewDataUrl: "data:image/png;base64,Aw==" }
    ] }] }
  ] };

  const html = renderNativeFileOverview({ analyzer: "pe", parsed: pe });
  const images = readOverviewDocument(html).getElementsByTagName("img");

  assert.equal(images.length, 1);
  assert.equal(images[0]!.getAttribute("src"), "data:image/png;base64,Ag==");
  assert.equal(images[0]!.getAttribute("alt"), "ICON / <icon> / LANGID ?");
  assert.deepEqual(readOverviewFacts(html), [["Largest resource", "PNG / 1"],
    ["Size", "100 B (100 bytes)"], ["Resource warnings", "1"]]);
});

void test("without an icon the largest local image is used and remote previews are excluded", () => {
  const pe = createBasePe();
  pe.resources = { top: [], detail: [{ typeName: "BITMAP", entries: [{ id: null, name: null,
    langs: [{ ...language(5), previewKind: "image", previewDataUrl: "data:image/png;base64,AQ==" },
      { ...language(10), lang: 0x409, previewKind: "image", previewDataUrl: "data:image/png;base64,Ag==" },
      { ...language(100), previewKind: "image", previewDataUrl: "https://example.invalid/image.png" }] }] }] };

  const html = renderNativeFileOverview({ analyzer: "pe", parsed: pe });

  assert.match(html, /data:image\/png;base64,Ag==/);
  assert.match(html, /BITMAP \/ \? \/ LANGID 0x0409/);
  assert.doesNotMatch(html, /example.invalid/);
});

void test("resources without images still have factual highlights and warnings stay supplemental", () => {
  const pe = createBasePe();
  pe.warnings = ["Recorded warning", "Second warning"];
  pe.resources = { top: [], detail: [{ typeName: "STRING", entries: [{ id: 1, name: null,
    langs: [language(8)] }] }] };

  const html = renderNativeFileOverview({ analyzer: "pe", parsed: pe });

  assert.equal(readOverviewDocument(html).getElementsByTagName("img").length, 0);
  assert.match(html, /data-analysis-origin="supplemental"/);
  assert.deepEqual(readOverviewFacts(html), [["Largest resource", "STRING / 1"], ["Size", "8 B (8 bytes)"],
    ["Warnings", "2"], ["First recorded warning", "Recorded warning"]]);
});

void test("empty, missing, ROM and unsupported formats do not produce fabricated cards", async () => {
  const pe = createBasePe();
  const rom = await parseForUi(createPeRomFile());
  const media = await parseForUi(createWebmFile());

  assert.equal(renderNativeFileOverview({ analyzer: "pe", parsed: pe }), "");
  pe.resources = { top: [], detail: [] };
  assert.equal(renderNativeFileOverview({ analyzer: "pe", parsed: pe }), "");
  assert.doesNotMatch(renderNativeFileOverview(rom), /analysis-resources|<table/);
  assert.equal(renderNativeFileOverview(media), "");
  assert.equal(renderNativeFileOverview({ analyzer: null, parsed: null }), "");
});

void test("ELF tiles expose source identifiers with a compact dependency highlight", async () => {
  const result = await parseForUi(createElfMetadataFile().file);
  assert.equal(result.analyzer, "elf");
  result.parsed.notes!.entries.unshift({ source: "auxiliary", name: "GNU", type: 1,
    typeName: "NT_GNU_ABI_TAG", value: "not a build ID", description: null, descSize: 0 });

  const html = renderNativeFileOverview(result);

  assert.deepEqual(readOverviewFacts(html), [["First string", "GCC"], ["Strings", "2"],
    ["Value", "000102030405060708090a0b0c0d0e0f10111213"], ["Source", 'Section ".note.gnu.build-id"'],
    ["First dependency", "libc.so.6"], ["Dependencies", "2"]]);
  assert.doesNotMatch(html, /<table|<ul|<ol|Architecture/);
});

void test("ELF missing metadata and an unavailable build ID remain explicit", async () => {
  const result = await parseForUi(createElfMetadataFile().file);
  assert.equal(result.analyzer, "elf");
  result.parsed.notes!.entries[0]!.value = null;

  assert.match(renderNativeFileOverview(result), /Unavailable/);
  delete result.parsed.comment;
  delete result.parsed.notes;
  delete result.parsed.dynamic;
  assert.equal(renderNativeFileOverview(result), "");
});
