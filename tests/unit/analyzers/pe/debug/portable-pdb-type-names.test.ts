import assert from "node:assert/strict";
import { test } from "node:test";
import { PortablePdbTypeNames } from "../../../../../analyzers/pe/debug/portable-pdb-type-names.js";
import { createClrMetadataTablesWithParameterNames } from "../../../../fixtures/pe-clr-metadata-tables.js";

void test("Portable PDB resolves TypeDef, TypeRef and chained TypeSpec names", () => {
  const metadata = createClrMetadataTablesWithParameterNames();
  metadata.typeRefs = [{ row: 1, name: "Decimal", namespace: "System", fullName: "System.Decimal",
    resolutionScope: { table: "AssemblyRef", tableId: 0x23, row: 1, raw: 6, valid: true } }];
  metadata.additionalTables = [{ tableId: 0x1b, rows: [
    { Signature: { type: "valuetype TypeRef#1" } },
    { Signature: { type: "valuetype TypeSpec#1" } },
    { Signature: { type: "class TypeDef#1" } }
  ] }];
  const names = new PortablePdbTypeNames(metadata);

  assert.equal(names.get({ tableId: 1, row: 1 }), "System.Decimal");
  assert.equal(names.get({ tableId: 2, row: 1 }), "Demo.Buffer");
  assert.equal(names.get({ tableId: 0x1b, row: 2 }), "System.Decimal");
  assert.equal(names.get({ tableId: 0x1b, row: 3 }), "Demo.Buffer");
  assert.equal(names.get({ tableId: 0x1b, row: 2 }), "System.Decimal");
});

void test("Portable PDB type names bound cycles and ignore absent or compound specifications", () => {
  const metadata = createClrMetadataTablesWithParameterNames();
  metadata.additionalTables = [{ tableId: 0x1b, rows: [
    { Signature: { type: "valuetype TypeSpec#2" } }, { Signature: { type: "valuetype TypeSpec#1" } },
    { Signature: { type: "int32[]" } }, { Signature: null }, { Signature: 1 },
    { Signature: { types: [] } }, { Signature: { type: null } }
  ] }];
  const names = new PortablePdbTypeNames(metadata);

  assert.equal(names.get({ tableId: 0x1b, row: 1 }), null);
  assert.equal(names.get({ tableId: 0x1b, row: 1 }), null);
  assert.equal(names.get({ tableId: 0x1b, row: 3 }), null);
  assert.equal(names.get({ tableId: 9, row: 1 }), null);
  assert.equal(names.get(undefined), null);
  assert.equal(new PortablePdbTypeNames(undefined).get({ tableId: 1, row: 1 }), null);
});
