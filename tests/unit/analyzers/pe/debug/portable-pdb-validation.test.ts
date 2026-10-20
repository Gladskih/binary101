import assert from "node:assert/strict";
import { test } from "node:test";
import { validatePortablePdbRows } from "../../../../../analyzers/pe/debug/portable-pdb-validation.js";
import { parseMetadataTableStream } from "../../../../../analyzers/pe/clr/metadata-table-reader.js";
import { ClrHeapReaders } from "../../../../../analyzers/pe/clr/metadata-heaps.js";
import { createPortablePdbStreams } from "../../../../fixtures/portable-pdb.js";

const createValidation = () => {
  const streams = createPortablePdbStreams();
  const issues: string[] = [];
  const refs = new Map([[0, 1], [6, 1]]);
  const parsed = parseMetadataTableStream(streams["#~"]!, "#~", issues, refs)!;
  const heaps = new ClrHeapReaders({ strings: streams["#Strings"]!, guid: streams["#GUID"]!,
    blob: streams["#Blob"]!, userString: null }, issues);
  return { parsed, heaps, refs, issues };
};

void test("Portable PDB validates heap references and accepts list-end sentinels", () => {
  const subject = createValidation();
  subject.parsed.tables.get(0x32)!.rows[0]!["VariableList"] = {
    table: "LocalVariable", tableId: 0x33, row: 2, raw: 2, valid: false
  };

  validatePortablePdbRows(subject.parsed, subject.heaps, subject.refs);

  assert.deepEqual(subject.issues, []);
});

void test("Portable PDB diagnoses invalid table indexes, IL ranges and method row counts", () => {
  const subject = createValidation();
  subject.refs.set(6, 2);
  subject.parsed.tables.get(0x32)!.rows[0]!["Length"] = 0x80000000;
  subject.parsed.tables.get(0x32)!.rows[0]!["Method"] = {
    table: "MethodDef", tableId: 6, row: 3, raw: 3, valid: false
  };

  validatePortablePdbRows(subject.parsed, subject.heaps, subject.refs);

  assert.match(subject.issues.join(" | "), /row count differs/);
  assert.match(subject.issues.join(" | "), /out-of-range table index/);
  assert.match(subject.issues.join(" | "), /IL range/);
});

void test("Portable PDB diagnoses nil required indexes, empty scopes and cyclic import parents", () => {
  const subject = createValidation();
  subject.parsed.tables.get(0x32)!.rows[0]!["Length"] = 0;
  subject.parsed.tables.get(0x32)!.rows[0]!["Method"] = {
    table: "MethodDef", tableId: 6, row: 0, raw: 0, valid: true
  };
  subject.parsed.tables.get(0x35)!.rows[0]!["Parent"] = {
    table: "ImportScope", tableId: 0x35, row: 1, raw: 1, valid: true
  };

  validatePortablePdbRows(subject.parsed, subject.heaps, subject.refs);

  assert.match(subject.issues.join(" | "), /required.*nil/);
  assert.match(subject.issues.join(" | "), /LocalScope.*empty/);
  assert.match(subject.issues.join(" | "), /ImportScope.*parent/);
});
