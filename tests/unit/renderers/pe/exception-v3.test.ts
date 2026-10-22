import assert from "node:assert/strict";
import { test } from "node:test";
import { renderExceptionV3 } from "../../../../renderers/pe/exception-v3.js";
import { createV3Statistics } from "../../../../analyzers/pe/exception/amd64/unwind-v3-statistics.js";
import { renderException } from "../../../../renderers/pe/exception.js";
import { createEmptyExceptionDirectory } from "../../../../analyzers/pe/exception/types.js";
import { DOMParser } from "@xmldom/xmldom";

const inventoryTables = (html: string) => {
  const document = new DOMParser({ onError: assert.fail }).parseFromString(`<root>${html}</root>`, "application/xml");
  return Array.from(document.getElementsByTagName("table"), table => {
    const caption = table.getElementsByTagName("caption")[0]!.textContent;
    const headings = Array.from(table.getElementsByTagName("th"), cell => cell.textContent);
    const rows = Array.from(table.getElementsByTagName("tbody")[0]!.getElementsByTagName("tr"), row => {
      const cells = row.getElementsByTagName("td");
      assert.equal(cells[1]!.getAttribute("class"), "peNumeric");
      return Array.from(cells, cell => cell.textContent);
    });
    assert.ok(table.textContent != null);
    assert.equal(table.textContent.replace(/\s/g, ""),
      `${caption}${headings.join("")}${rows.flat().join("")}`.replace(/\s/g, ""));
    return { caption, headings, rows };
  });
};

void test("V3 statistics omit empty output and empty inventories", () => {
  const statistics = createV3Statistics();

  assert.equal(renderExceptionV3(statistics), "");
  const html = renderExceptionV3({ ...statistics, blockCount: 1 });
  assert.match(html, /preview/);
  assert.match(html, /Inventories count distinct referenced winding-operation records/);
  assert.match(html, /shared prolog and epilog references count once/);
  assert.doesNotMatch(html, /<table|<details|<dl>/);
  assert.deepEqual(Array.from(new DOMParser({ onError: assert.fail })
    .parseFromString(`<root>${html}</root>`, "application/xml").documentElement!.childNodes,
  node => node.nodeName), ["p"]);
});

void test("V3 statistics show bounded semantic inventories, allocation bins and readable extrema", () => {
  const html = renderExceptionV3({ ...createV3Statistics(), blockCount: 1,
    operationCounts: { PUSH: 2, ALLOC_SMALL: 1 }, registerCounts: { R16: 1, R8: 1, RBX: 3 },
    allocationCounts: { 0: 1, 8: 2, 15: 1, 1024: 1 }, prologSizeCounts: { 4: 1, 256: 1 },
    canonicalFrameTypeCounts: { 255: 1 } });

  assert.match(html, /Winding operations/);
  assert.match(html, /ALLOC SMALL/);
  assert.match(html, /Largest explicit stack allocation/);
  assert.match(html, /Largest prolog/);
  assert.match(html, /Largest explicit stack allocation<\/dt><dd>1 KB \(1024 bytes\)<\/dd>/);
  assert.match(html, /Largest prolog<\/dt><dd>256 B \(256 bytes\)<\/dd>/);
  assert.match(html, /Registers referenced/);
  assert.match(html, /OS-defined canonical frame types/);
  assert.match(html, /Type 255/);
  assert.match(html, /<th class="peNumeric">Count<\/th>/);
  assert.ok(html.indexOf(">RBX<") < html.indexOf(">R8<"));
  assert.ok(html.indexOf(">R8<") < html.indexOf(">R16<"));
  assert.doesNotMatch(html, /0x|<th>RVA|<details/);
  assert.deepEqual(inventoryTables(html), [
    { caption: "Winding operations", headings: ["Operation", "Count"], rows: [["PUSH", "2"], ["ALLOC SMALL", "1"]] },
    { caption: "Registers referenced by winding operations", headings: ["Register", "Count"],
      rows: [["RBX", "3"], ["R8", "1"], ["R16", "1"]] },
    { caption: "Explicit stack allocation distribution", headings: ["Allocation size", "Count"],
      rows: [["0 bytes", "1"], ["8 B to < 16 B", "3"], ["1 KiB to < 2 KiB", "1"]] },
    { caption: "OS-defined canonical frame types", headings: ["Frame type", "Count"], rows: [["Type 255", "1"]] }
  ]);
});

void test("V3 statistics escape inventory labels", () => {
  const html = renderExceptionV3({ ...createV3Statistics(), blockCount: 1,
    registerCounts: { '<img src=x onerror="boom">&': 1 } });

  assert.doesNotMatch(html, /<img/);
  assert.match(html, /&lt;img/);
  assert.match(html, /&amp;/);
});

void test("V3 allocation bins stay exact and ordered at MiB and GiB boundaries", () => {
  const html = renderExceptionV3({ ...createV3Statistics(), blockCount: 1,
    allocationCounts: { 1048576: 1, 1073741824: 1 } });

  assert.deepEqual(inventoryTables(html)[0]?.rows, [
    ["1 MiB to < 2 MiB", "1"], ["1 GiB to < 2 GiB", "1"]
  ]);
});

void test("Exception renderer exposes the V3 summary and inventories through its existing entry point", () => {
  const out: string[] = [];
  renderException({ ...createEmptyExceptionDirectory([], "amd64"), unwindInfoV3: {
    ...createV3Statistics(), blockCount: 1, epilogCount: 2, inheritedEpilogCount: 1,
    largePrologCount: 1, largeEpilogCount: 2, operationCounts: { PUSH: 1 }
  } }, out);
  const html = out.join("");

  assert.match(html, /UNWIND_INFO v3 blocks<\/dt><dd>1<\/dd>/);
  assert.match(html, /UNWIND_INFO v3 epilogs<\/dt><dd>2<\/dd>/);
  assert.match(html, /UNWIND_INFO v3 inherited epilogs<\/dt><dd>1<\/dd>/);
  assert.match(html, /UNWIND_INFO v3 LARGE prologs<\/dt><dd>1<\/dd>/);
  assert.match(html, /UNWIND_INFO v3 LARGE epilogs<\/dt><dd>2<\/dd>/);
  assert.match(html, /<caption>Winding operations<\/caption>/);
});

void test("Exception V3 summaries omit absent versions and unused optional encodings", () => {
  const out: string[] = [];
  renderException({ ...createEmptyExceptionDirectory([], "amd64"),
    unwindInfoVersion1Count: 0, unwindInfoVersion2Count: 0, epilogUnwindInfoCount: 0, epilogScopeCount: 0,
    unwindInfoV3: { ...createV3Statistics(), blockCount: 1, epilogCount: 1 }
  }, out);
  const html = out.join("");

  assert.match(html, /UNWIND_INFO v3 blocks/);
  assert.match(html, /UNWIND_INFO v3 epilogs/);
  assert.doesNotMatch(html, /UNWIND_INFO v1|UNWIND_INFO v2|LARGE|inherited epilogs/);
  assert.match(html, /Missing\/invalid ranges/);
});

void test("Mixed-version inventories retain v1 and v2 statistics alongside v3", () => {
  const out: string[] = [];
  renderException({ ...createEmptyExceptionDirectory([], "amd64"), functionCount: 3,
    beginRvas: [16, 32, 48], rangeLengths: [4, 4, 4], uniqueUnwindInfoCount: 3,
    unwindInfoVersion1Count: 1, unwindInfoVersion2Count: 1, epilogUnwindInfoCount: 1, epilogScopeCount: 2,
    unwindInfoV3: { ...createV3Statistics(), blockCount: 1 }
  }, out);
  const html = out.join("");

  assert.match(html, /UNWIND_INFO v1 blocks<\/dt><dd>1<\/dd>/);
  assert.match(html, /UNWIND_INFO v2 blocks<\/dt><dd>1<\/dd>/);
  assert.match(html, /UNWIND_INFO v2 epilog scopes<\/dt><dd>2<\/dd>/);
  assert.match(html, /UNWIND_INFO v3 blocks<\/dt><dd>1<\/dd>/);
});
