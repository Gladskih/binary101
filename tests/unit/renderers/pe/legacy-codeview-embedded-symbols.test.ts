import assert from "node:assert/strict";
import { test } from "node:test";
import { buildLegacyCodeViewEmbeddedSymbolTables } from "../../../../renderers/pe/legacy-codeview-embedded-symbols.js";
import { createLegacyCodeViewInfo } from "../../../fixtures/pe-legacy-codeview-view.js";

void test("CodeView embedded symbol tables preserve names and summarize all enclosed record kinds", () => {
  const info = createLegacyCodeViewInfo();
  info.directories[0]!.subsections.push({ type: 0x125, module: 3, offset: 0, size: 0,
    data: { kind: "symbols", records: [{ type: 0x113b, children: [
      { type: 0x110d, name: "<removed>" }, { type: 0x110d, name: "" }, { type: 6 }] }] } });
  info.directories[0]!.subsections.push({ type: 0x121, module: 4, offset: 0, size: 0,
    data: { kind: "types", records: [{ type: 0x20c, symbols: [{ type: 0x110e, name: "referenced" }] }] } });

  assert.deepEqual(buildLegacyCodeViewEmbeddedSymbolTables(info), [
    { key: "embeddedSymbols", title: "Embedded symbol names",
      columns: ["Directory", "Module", "Container", "Symbol kind", "Name"], rows: [
        ["1", "3", "Discarded symbols", "Global data", "<removed>"],
        ["1", "3", "Discarded symbols", "Global data", "(unnamed)"],
        ["1", "4", "Referenced symbol", "Public symbol", "referenced"]
      ] },
    { key: "embeddedSymbolStats", title: "Embedded symbol statistics",
      columns: ["Directory", "Module", "Container", "Symbol kind", "Records"], rows: [
        ["1", "3", "Discarded symbols", "Global data", "2"], ["1", "3", "Discarded symbols", "Scope end", "1"],
        ["1", "4", "Referenced symbol", "Public symbol", "1"]
      ] }
  ]);
});

void test("CodeView embedded symbol tables omit empty containers and top-level names", () => {
  const info = createLegacyCodeViewInfo();
  info.directories[0]!.subsections.push({ type: 0x125, module: 3, offset: 0, size: 0,
    data: { kind: "symbols", records: [{ type: 0x113b, children: [] }] } });
  info.directories[0]!.subsections.push({ type: 0x125, module: 4, offset: 0, size: 0 });

  assert.deepEqual(buildLegacyCodeViewEmbeddedSymbolTables(info), []);
  assert.deepEqual(buildLegacyCodeViewEmbeddedSymbolTables({ signature: "NB09", directories: [] }), []);
});
