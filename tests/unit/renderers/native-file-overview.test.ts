import assert from "node:assert/strict";
import { test } from "node:test";
import { renderNativeFileOverview } from "../../../renderers/native-file-overview.js";
import { createBasePe, createPeSection } from "../../fixtures/pe-renderer-headers-fixture.js";
import { parseForUi } from "../../../analyzers/index.js";
import { createElfMetadataFile } from "../../fixtures/elf-metadata-file.js";
import { createMkvFile } from "../../fixtures/mkv-base-fixtures.js";
import { createWebmFile } from "../../fixtures/webm-base-fixtures.js";
import { createPeRomFile } from "../../fixtures/sample-files-pe.js";
import { DOMParser } from "@xmldom/xmldom";

const readTables = (html: string) => Array.from(new DOMParser({ onError: assert.fail })
  .parseFromString(`<root>${html}</root>`, "application/xml").getElementsByTagName("table"))
  .map(table => {
    const headers = Array.from(table.getElementsByTagName("th"));
    assert.ok(headers.every(header => header.getAttribute("scope") === "col"));
    const rows = Array.from(table.getElementsByTagName("tbody")[0]!.getElementsByTagName("tr"))
      .map(row => Array.from(row.getElementsByTagName("td"), cell => cell.textContent));
    assert.equal(table.textContent, headers.map(header => header.textContent).join("") +
      rows.flat().join(""));
    return { headers: headers.map(header => header.textContent), rows };
  });

void test("PE overview reads actual VERSION strings and preserves their provenance", () => {
  const pe = createBasePe();
  pe.resources = { top: [], detail: [{ typeName: "VERSION", entries: [{ id: 1, name: null,
    langs: [{ lang: 0x409, size: 0, codePage: 0, dataRVA: 0, dataFileOffset: null, reserved: 0,
      versionInfo: { stringValues: [{ table: "040904E4", key: "FileDescription", value: "<sample>" },
        { table: "040904E4", key: "CompanyName", value: "A&B" },
        { table: "040904E4", key: "ProductName", value: "Product" },
        { table: "040904E4", key: "ProductVersion", value: "product version" },
        { table: "040904E4", key: "OriginalFilename", value: "original.exe" }] } }] }] }] };

  const html = renderNativeFileOverview({ analyzer: "pe", parsed: pe });

  assert.match(html, /VERSION/);
  assert.match(html, /FileDescription/);
  assert.match(html, /040904E4/);
  assert.match(html, /&lt;sample&gt;/);
  assert.match(html, /A&amp;B/);
  assert.match(html, /ProductName<\/td><td>Product/);
  assert.match(html, /ProductVersion<\/td><td>product version/);
  assert.match(html, /OriginalFilename<\/td><td>original.exe/);
  assert.doesNotMatch(html, /Architecture|COFF.Machine|Subsystem/);
  assert.match(html, /data-workspace-source="resources"/);
  assert.deepEqual(readTables(html), [{ headers: ["StringFileInfo key", "Value", "String table"],
    rows: [["FileDescription", "<sample>", "040904E4"], ["CompanyName", "A&B", "040904E4"],
      ["ProductName", "Product", "040904E4"], ["ProductVersion", "product version", "040904E4"],
      ["OriginalFilename", "original.exe", "040904E4"]] }]);
});

void test("PE without identification metadata shows native section raw ranges without invented conclusions", () => {
  const pe = createBasePe();
  pe.sections = [createPeSection(".text", { pointerToRawData: 512, sizeOfRawData: 1024 })];

  const html = renderNativeFileOverview({ analyzer: "pe", parsed: pe });

  assert.match(html, /PointerToRawData/);
  assert.match(html, /SizeOfRawData/);
  assert.match(html, /\.text/);
  assert.match(html, /0x00000200/);
  assert.doesNotMatch(html, /safe|malicious|compiler|Architecture/i);
  assert.match(html, /data-workspace-source="section-headers"/);
  assert.deepEqual(readTables(html), [{ headers: ["Name", "PointerToRawData", "SizeOfRawData"],
    rows: [[".text", "0x00000200", "1 KB (1024 bytes)"]] }]);
});

void test("unknown formats do not acquire fabricated metadata", () => {
  assert.equal(renderNativeFileOverview({ analyzer: null, parsed: null }), "");
});

void test("ROM sections are shown without treating them as Windows version resources", async () => {
  const result = await parseForUi(createPeRomFile());

  const html = renderNativeFileOverview(result);

  assert.match(html, /Section headers/);
  assert.doesNotMatch(html, /VERSION/);
});

void test("an empty PE has no fabricated section table", () => {
  const pe = createBasePe();
  pe.sections = [];
  pe.resources = { top: [], detail: [] };

  assert.equal(renderNativeFileOverview({ analyzer: "pe", parsed: pe }), "");
});

void test("VERSION variants retain names, unknown language and each string table", () => {
  const pe = createBasePe();
  pe.resources = { top: [], detail: [{ typeName: "VERSION", entries: [{ id: null, name: "named",
    langs: [{ lang: null, size: 0, codePage: 0, dataRVA: 0, dataFileOffset: null, reserved: 0,
      versionInfo: { stringValues: [{ table: "first", key: "FileVersion", value: "one" },
        { table: "second", key: "FileVersion", value: "two" }] } }] }] }] };

  const html = renderNativeFileOverview({ analyzer: "pe", parsed: pe });

  assert.match(html, /VERSION \/ named \/ LANGID \?/);
  assert.match(html, /<td>one<\/td><td>first/);
  assert.match(html, /<td>two<\/td><td>second/);
});

void test("resources without identification strings fall back to native sections", () => {
  const pe = createBasePe();
  pe.sections = [createPeSection(".data")];
  pe.resources = { top: [], detail: [{ typeName: "VERSION", entries: [{ id: null, name: null,
    langs: [{ lang: null, size: 0, codePage: 0, dataRVA: 0, dataFileOffset: null, reserved: 0 }] }] }] };

  const html = renderNativeFileOverview({ analyzer: "pe", parsed: pe });

  assert.match(html, /Section headers/);
  assert.doesNotMatch(html, /VERSION/);
});

void test("ELF identification retains native field names and links to its sources", async () => {
  const result = await parseForUi(createElfMetadataFile().file);
  assert.equal(result.analyzer, "elf");

  const html = renderNativeFileOverview(result);

  assert.match(html, /NT_GNU_BUILD_ID/);
  assert.match(html, /\.comment/);
  assert.match(html, /DT_NEEDED/);
  assert.match(html, /data-workspace-source="notes"/);
  assert.match(html, /data-workspace-source="linking"/);
  assert.doesNotMatch(html, /Architecture/);
  assert.match(html, /data-workspace-source="debug"/);
  assert.deepEqual(readTables(html), [
    { headers: ["String"], rows: [["GCC"], ["Clang"]] },
    { headers: ["Source", "Value"], rows: [['Section ".note.gnu.build-id"',
      "000102030405060708090a0b0c0d0e0f10111213"]] },
    { headers: ["String"], rows: [["libc.so.6"], ["libm.so.6"]] }
  ]);
});

void test("ELF missing identification metadata produces no empty summary tables", async () => {
  const result = await parseForUi(createElfMetadataFile().file);
  assert.equal(result.analyzer, "elf");
  delete result.parsed.comment;
  delete result.parsed.notes;
  delete result.parsed.dynamic;

  assert.equal(renderNativeFileOverview(result), "");
});

void test("ELF preserves an unavailable build ID and escapes needed library names", async () => {
  const result = await parseForUi(createElfMetadataFile(["<library>.so"]).file);
  assert.equal(result.analyzer, "elf");
  assert.ok(result.parsed.notes);
  result.parsed.notes.entries = [{ source: "native source", name: "GNU", type: 3,
    typeName: "NT_GNU_BUILD_ID", value: null, description: null, descSize: 0 }];

  const html = renderNativeFileOverview(result);

  assert.match(html, /native source<\/td><td>Unavailable/);
  assert.match(html, /&lt;library&gt;.so/);
});

void test("Matroska overview shows the title and native track fields", async () => {
  const result = await parseForUi(createMkvFile());

  const html = renderNativeFileOverview(result);

  assert.match(html, /Info.Title/);
  assert.match(html, /Example Matroska/);
  assert.match(html, /TrackNumber/);
  assert.match(html, /V_MPEG4\/ISO\/AVC/);
  assert.match(html, /A_AAC/);
  assert.deepEqual(readTables(html), [{
    headers: ["TrackNumber", "TrackType", "CodecID", "Name", "Language"],
    rows: [["1", "1 (Video)", "V_MPEG4/ISO/AVC", "", "und (default)"],
      ["2", "2 (Audio)", "A_AAC", "", "und (default)"]]
  }]);
});

void test("WebM overview handles an absent segment, title and tracks", async () => {
  const result = await parseForUi(createWebmFile());
  assert.equal(result.analyzer, "webm");
  assert.ok(result.parsed.segment);
  result.parsed.segment.info = null;
  result.parsed.segment.tracks = [];

  assert.equal(renderNativeFileOverview(result), "");
  result.parsed.segment = null;
  assert.equal(renderNativeFileOverview(result), "");
});
