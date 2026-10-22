import assert from "node:assert/strict";
import { test } from "node:test";
import { buildLegacyCodeViewSymbolStringTables } from "../../../../renderers/pe/legacy-codeview-symbol-tables.js";
import { createLegacyCodeViewInfo } from "../../../fixtures/pe-legacy-codeview-view.js";

void test("CodeView stored symbol strings preserve annotations, compiler settings and mapped PDB paths", () => {
  const info = createLegacyCodeViewInfo();
  info.directories[0]!.subsections.push({ type: 0x125, module: 3, offset: 0, size: 0,
    data: { kind: "symbols", records: [{ type: 0x1019, strings: ["first", "", "third"] },
      { type: 0x1013, name: "compiler", strings: ["cwd", "<folder>"] },
      { type: 0x1116, name: "compiler", strings: ["exe", "tool.exe", "flags", "/opt"] },
      { type: 0x1161, strings: ["source.pdb", "destination.pdb"] }] } });
  const tables = buildLegacyCodeViewSymbolStringTables(info);

  assert.deepEqual(tables, [{ key: "symbolStrings", title: "Stored symbol strings",
    columns: ["Directory", "Module", "Symbol kind", "Field", "Text"], rows: [
      ["1", "3", "Annotations", "String 1", "first"], ["1", "3", "Annotations", "String 2", "(empty)"],
      ["1", "3", "Annotations", "String 3", "third"], ["1", "3", "Compiler", "cwd", "<folder>"],
      ["1", "3", "Compiler", "exe", "tool.exe"], ["1", "3", "Compiler", "flags", "/opt"],
      ["1", "3", "PDB mapping", "Source PDB", "source.pdb"],
      ["1", "3", "PDB mapping", "Destination PDB", "destination.pdb"]
    ] }]);
});

void test("CodeView truncated environment pairs retain their keys and distinguish missing and empty values", () => {
  const info = createLegacyCodeViewInfo();
  info.directories.push({ flags: 0, subsections: [{ type: 0x125, module: 4, offset: 0, size: 0,
    data: { kind: "symbols", records: [{ type: 0x113d, strings: ["", "", "orphan"] }] } }] });

  assert.deepEqual(buildLegacyCodeViewSymbolStringTables(info)[0]!.rows, [
    ["2", "4", "Environment", "(empty key)", "(empty)"], ["2", "4", "Environment", "orphan", "(missing value)"]
  ]);
});

void test("CodeView symbol text tables omit empty and absent payloads and preserve subsection identity", () => {
  const info = createLegacyCodeViewInfo();
  info.directories[0]!.subsections.push({ type: 0x125, module: 4, offset: 0, size: 0,
    data: { kind: "symbols", records: [{ type: 0x1019, strings: [] }] } });
  info.directories[0]!.subsections.push({ type: 0x125, module: 5, offset: 0, size: 0 });

  assert.deepEqual(buildLegacyCodeViewSymbolStringTables(info), []);
  assert.deepEqual(buildLegacyCodeViewSymbolStringTables({ signature: "NB09", directories: [] }), []);
});

void test("CodeView symbol text keeps record ordering across multiple modules", () => {
  const info = createLegacyCodeViewInfo();
  info.directories[0]!.subsections.push({ type: 0x125, module: 4, offset: 0, size: 0,
    data: { kind: "symbols", records: [{ type: 0x1019, strings: ["first"] }] } });
  info.directories[0]!.subsections.push({ type: 0x125, module: 5, offset: 0, size: 0,
    data: { kind: "symbols", records: [{ type: 0xffff, strings: ["second"] }] } });

  assert.deepEqual(buildLegacyCodeViewSymbolStringTables(info)[0]!.rows, [
    ["1", "4", "Annotations", "String 1", "first"], ["1", "5", "Symbol record 0xffff", "String 1", "second"]
  ]);
});
