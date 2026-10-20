import assert from "node:assert/strict";
import { test } from "node:test";
import { ClrHeapReaders } from "../../../../../analyzers/pe/clr/metadata-heaps.js";
import { PortablePdbImportReader } from "../../../../../analyzers/pe/debug/portable-pdb-imports.js";

const subject = (imports: number[]) => {
  // Portable PDB Imports Blob, kinds 1 through 9. #Blob indexes are compressed integers.
  const namespace = new TextEncoder().encode("System.Collections");
  const alias = new TextEncoder().encode("alias");
  const blob = Uint8Array.from([0, namespace.length, ...namespace, alias.length, ...alias,
    imports.length, ...imports]);
  const issues: string[] = [];
  const heaps = new ClrHeapReaders({ blob, strings: null, guid: null, userString: null }, issues);
  return { issues, reader: new PortablePdbImportReader(heaps,
    new Map([[0x23, 1], [0x01, 1], [0x02, 1], [0x1b, 1]])), index: 26 };
};

void test("Portable PDB imports decode all nine documented kinds and retain aliases", () => {
  // Namespace blob index 1, alias index 20, TypeRef row 1 encodes as (1 << 2) | 1 = 5.
  const { reader, index, issues } = subject([
    1, 1, 2, 1, 1, 3, 5, 4, 20, 1, 5, 20, 6, 20, 1, 7, 20, 1, 8, 20, 1, 1, 9, 20, 5
  ]);

  assert.deepEqual(reader.read(index), [
    { kind: 1, targetNamespace: "System.Collections" },
    { kind: 2, targetAssembly: 1, targetNamespace: "System.Collections" },
    { kind: 3, targetType: { tableId: 0x01, row: 1 } },
    { kind: 4, alias: "alias", targetNamespace: "System.Collections" },
    { kind: 5, alias: "alias" },
    { kind: 6, alias: "alias", targetAssembly: 1 },
    { kind: 7, alias: "alias", targetNamespace: "System.Collections" },
    { kind: 8, alias: "alias", targetAssembly: 1, targetNamespace: "System.Collections" },
    { kind: 9, alias: "alias", targetType: { tableId: 0x01, row: 1 } }
  ]);
  assert.deepEqual(issues, []);
  assert.equal(reader.read(index), reader.read(index));
});

void test("Portable PDB imports preserve decoded records before an unsupported kind", () => {
  const { reader, index, issues } = subject([1, 1, 10, 0]);

  assert.deepEqual(reader.read(index), [{ kind: 1, targetNamespace: "System.Collections" }]);
  assert.match(issues.join(" | "), /unsupported import kind 10/);
  reader.read(index);
  assert.equal(issues.length, 1);
});

void test("Portable PDB imports diagnose truncated operands and malformed integers", () => {
  const short = subject([8, 20, 1]);
  const malformed = subject([255]);

  assert.deepEqual(short.reader.read(short.index), []);
  assert.match(short.issues.join(" | "), /compressed integer/);
  assert.deepEqual(malformed.reader.read(malformed.index), []);
  assert.match(malformed.issues.join(" | "), /compressed integer/);
});

void test("Portable PDB imports validate assembly and type-system row references", () => {
  const { reader, index, issues } = subject([2, 0, 1, 3, 0, 3, 7, 3, 9, 3, 4, 3, 6]);

  assert.equal(reader.read(index).length, 6);
  assert.match(issues.join(" | "), /AssemblyRef.*out of range/);
  assert.match(issues.join(" | "), /type.*out of range/);
});

void test("Portable PDB imports handle absent, empty and unreadable text blobs", () => {
  const { reader, index, issues } = subject([1, 127]);

  assert.deepEqual(reader.read(0), []);
  assert.deepEqual(reader.read(0xffff), []);
  assert.deepEqual(reader.read(index), [{ kind: 1, targetNamespace: null }]);
  assert.match(issues.join(" | "), /outside the heap/);
});

void test("Portable PDB imports share UTF-8 decoding and diagnostics across blob references", () => {
  const issues: string[] = [];
  const heaps = new ClrHeapReaders({ blob: Uint8Array.of(0, 1, 255, 4, 1, 1, 1, 1),
    strings: null, guid: null, userString: null }, issues);
  const reader = new PortablePdbImportReader(heaps, new Map());

  assert.deepEqual(reader.read(3), [
    { kind: 1, targetNamespace: null }, { kind: 1, targetNamespace: null }
  ]);
  assert.equal(issues.filter(issue => issue.includes("not valid UTF-8")).length, 1);
});
