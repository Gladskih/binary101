import assert from "node:assert/strict";
import { test } from "node:test";
import { buildLegacyCodeViewIndexTables } from "../../../../renderers/pe/legacy-codeview-index-tables.js";
import { createLegacyCodeViewInfo } from "../../../fixtures/pe-legacy-codeview-view.js";

void test("CodeView indexes summarize occupancy and retain meaningful section names", () => {
  const info = createLegacyCodeViewInfo();
  info.directories[0]!.subsections.push({ type: 0x12a, module: 0xffff, offset: 0, size: 0,
    data: { kind: "symbols", records: [], nameIndex: { algorithm: 10, counts: [0, 2, 1, 2] },
      addressIndex: { algorithm: 12, counts: [3, 0, 2] } } });
  const tables = buildLegacyCodeViewIndexTables(info);

  assert.deepEqual(tables, [
    { key: "indexes", title: "Symbol index statistics (declared counts)",
      columns: ["Directory", "Module", "Subsection", "Index kind", "Algorithm", "Groups", "Nonempty groups",
        "References", "Largest group"], rows: [
        ["1", "65535", "Global publics", "Names", "XOR/rotate DWORD checksum", "4", "3", "5", "2"],
        ["1", "65535", "Global publics", "Addresses", "Grouped section sort", "3", "2", "5", "3"] ] },
    { key: "buckets", title: "Name hash bucket occupancy",
      columns: ["Directory", "Module", "Subsection", "References per bucket", "Buckets"],
      rows: [["1", "65535", "Global publics", "0", "1"], ["1", "65535", "Global publics", "1", "1"],
        ["1", "65535", "Global publics", "2", "2"]] },
    { key: "indexedSections", title: "Indexed symbols by logical section",
      columns: ["Directory", "Module", "Subsection", "Section", "References"],
      rows: [["1", "65535", "Global publics", ".text", "3"], ["1", "65535", "Global publics", "#3", "2"]] }
  ]);
});

void test("CodeView older index algorithms keep distinct readable names", () => {
  const info = createLegacyCodeViewInfo();
  info.directories[0]!.subsections.push({ type: 0x12a, module: 1, offset: 0, size: 0,
    data: { kind: "symbols", records: [], nameIndex: { algorithm: 0 }, addressIndex: { algorithm: 5, counts: [1] } } });
  info.directories[0]!.subsections.push({ type: 0x12a, module: 2, offset: 0, size: 0,
    data: { kind: "symbols", records: [], nameIndex: { algorithm: 6, counts: [1] },
      addressIndex: { algorithm: 8, counts: [1] } } });
  const tables = buildLegacyCodeViewIndexTables(info);

  assert.deepEqual(tables[0]!.rows.map(row => row[4]),
    ["No index", "Aligned section sort", "Shifted byte sum", "Modified section sort"]);
});

void test("CodeView unknown or malformed index layouts show algorithms without fabricated counts", () => {
  const info = createLegacyCodeViewInfo();
  info.directories[0]!.subsections.push({ type: 0x129, module: 2, offset: 0, size: 0,
    data: { kind: "symbols", records: [], nameIndex: { algorithm: 99 }, addressIndex: { algorithm: 0 } } });
  const tables = buildLegacyCodeViewIndexTables(info);

  assert.equal(tables.length, 1);
  assert.deepEqual(tables[0]!.rows, [
    ["1", "2", "Global symbols", "Names", "Unsupported algorithm 99", "—", "—", "—", "—"],
    ["1", "2", "Global symbols", "Addresses", "No index", "—", "—", "—", "—"]
  ]);
});

void test("CodeView empty decoded indexes keep zero statistics without empty distributions", () => {
  const info = createLegacyCodeViewInfo();
  info.directories[0]!.subsections.push({ type: 0x134, module: 3, offset: 0, size: 0,
    data: { kind: "symbols", records: [], nameIndex: { algorithm: 2, counts: [] },
      addressIndex: { algorithm: 4, counts: [] } } });
  const tables = buildLegacyCodeViewIndexTables(info);

  assert.equal(tables.length, 1);
  assert.deepEqual(tables[0]!.rows, [
    ["1", "3", "Static symbols", "Names", "Byte sum", "0", "0", "0", "0"],
    ["1", "3", "Static symbols", "Addresses", "Section sort", "0", "0", "0", "0"]
  ]);
});

void test("CodeView logical section names survive zero references and missing string references", () => {
  const info = createLegacyCodeViewInfo();
  info.directories[0]!.subsections.push({ type: 0x12d, module: 0, offset: 0, size: 0,
    data: { kind: "segmentMap", logicalCount: 3, segments: [
      { flags: 0, overlay: 0, group: 0, frame: 0, name: 0, className: 0, offset: 0, size: 0 },
      { flags: 0, overlay: 0, group: 0, frame: 0, name: 99, className: 0, offset: 0, size: 0 },
      { flags: 0, overlay: 0, group: 0, frame: 0, name: 6, className: 0, offset: 0, size: 0 }
    ] } });
  info.directories[0]!.subsections.push({ type: 0x12a, module: 0xffff, offset: 0, size: 0,
    data: { kind: "symbols", records: [], addressIndex: { algorithm: 8, counts: [0, 2, 0] } } });
  const tables = buildLegacyCodeViewIndexTables(info);

  assert.deepEqual(tables.find(table => table.key === "indexedSections")!.rows, [
    ["1", "65535", "Global publics", ".text", "0"], ["1", "65535", "Global publics", "#2", "2"],
    ["1", "65535", "Global publics", "CODE", "0"]
  ]);
});

void test("CodeView generations resolve names independently and preserve numeric occupancy order", () => {
  const info = createLegacyCodeViewInfo();
  info.directories.push({ flags: 0, subsections: [{ type: 0x12a, module: 1, offset: 0, size: 0,
    data: { kind: "symbols", records: [], nameIndex: { algorithm: 6, counts: [10, 0, 2, 2] },
      addressIndex: { algorithm: 5, counts: [1, 0] } } }] });
  const tables = buildLegacyCodeViewIndexTables(info);

  assert.deepEqual(tables.find(table => table.key === "buckets")!.rows, [
    ["2", "1", "Global publics", "0", "1"], ["2", "1", "Global publics", "2", "2"],
    ["2", "1", "Global publics", "10", "1"]
  ]);
  assert.deepEqual(tables.find(table => table.key === "indexedSections")!.rows, [["2", "1", "Global publics", "#1", "1"]]);
});

void test("CodeView index tables omit absent data and empty input", () => {
  const info = createLegacyCodeViewInfo();
  info.directories[0]!.subsections.push({ type: 0x12a, module: 1, offset: 0, size: 0 });

  assert.deepEqual(buildLegacyCodeViewIndexTables(info), []);
  assert.deepEqual(buildLegacyCodeViewIndexTables({ signature: "NB09", directories: [] }), []);
});
