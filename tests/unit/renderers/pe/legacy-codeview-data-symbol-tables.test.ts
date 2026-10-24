import assert from "node:assert/strict";
import { test } from "node:test";
import { buildLegacyCodeViewDataSymbolTables } from "../../../../renderers/pe/legacy-codeview-data-symbol-tables.js";
import { createLegacyCodeViewInfo } from "../../../fixtures/pe-legacy-codeview-view.js";

void test("CodeView data symbol rows retain type links, segment references and unknown public flags", () => {
  const info = createLegacyCodeViewInfo();
  const section = info.directories[0]!.subsections.find(value => value.data?.kind === "symbols")!;
  section.data = { kind: "symbols", records: [
    { type: 0x110c, name: "globalValue", data: { kind: "data", typeIndex: 4097,
      location: { segment: 9, offset: 4660 } } },
    { type: 0x110e, name: "publicFunction", data: { kind: "public", publicFlags: 0x80000003,
      location: { segment: 2, offset: 80 } } },
    { type: 0x1103, name: "inner", data: { kind: "block", codeLength: 12,
      location: { segment: 1, offset: 4 }, scopeOffsets: { parent: 32, end: 64 } } },
    { type: 0x1105, name: "marker", data: { kind: "label", location: { segment: 1, offset: 8 },
      flags: 0xd5 } },
    { type: 0x110e, data: { kind: "public" } },
    { type: 0x1103, name: "incompleteBlock", data: { kind: "block" } }
  ] };

  assert.deepEqual(buildLegacyCodeViewDataSymbolTables(info), [{ key: "dataSymbols",
    title: "Data, public, block and label symbols",
    columns: ["Directory", "Module", "Container", "Symbol kind", "Name", "Type reference",
      "Stored segment:offset", "Code length", "Raw parent/end offsets", "Public flags", "Symbol flags"],
    rows: [
      ["1", "1", "(top level)", "Local data", "globalValue", "Type index 4097", "9:4660",
        "not a block", "unavailable", "(not public)", "unavailable"],
      ["1", "1", "(top level)", "Public symbol", "publicFunction", "unavailable", "2:80",
        "not a block", "unavailable", "Code, Function, Unknown bits 0x80000000", "unavailable"],
      ["1", "1", "(top level)", "Block", "inner", "unavailable", "1:4", "12",
        "parent 32; end 64", "(not public)", "unavailable"],
      ["1", "1", "(top level)", "Label", "marker", "unavailable", "1:8", "not a block",
        "unavailable", "(not public)",
        "Frame pointer present, Far return, Not reached, No inline, Optimized debug information"],
      ["1", "1", "(top level)", "Public symbol", "(name unavailable)", "unavailable", "unavailable",
        "not a block", "unavailable", "unavailable", "unavailable"],
      ["1", "1", "(top level)", "Block", "incompleteBlock", "unavailable", "unavailable",
        "unavailable", "unavailable", "(not public)", "unavailable"]
    ] }]);
});

void test("CodeView data symbol tables omit absent records and show zero public flags", () => {
  const info = createLegacyCodeViewInfo();
  const section = info.directories[0]!.subsections.find(value => value.data?.kind === "symbols")!;
  section.data = { kind: "symbols", records: [{ type: 0x110e, data: { kind: "public", publicFlags: 0 } }] };

  assert.deepEqual(buildLegacyCodeViewDataSymbolTables(info)[0]?.rows[0]?.slice(9), ["None", "unavailable"]);
  assert.deepEqual(buildLegacyCodeViewDataSymbolTables(createLegacyCodeViewInfo()), []);
});
