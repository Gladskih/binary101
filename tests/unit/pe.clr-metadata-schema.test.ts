"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  codedIndexSchemaByName,
  metadataToken,
  tableNameById,
  tableSchemaById
} from "../../analyzers/pe/clr/metadata-schema.js";

void test("metadata schema helpers expose ECMA-335 table names and fallbacks", () => {
  assert.strictEqual(tableSchemaById(0x20)?.name, "Assembly");
  assert.strictEqual(tableNameById(0x23), "AssemblyRef");
  assert.strictEqual(tableNameById(0x7e), "TABLE_7e");
});

void test("metadata schema helpers expose coded-index tag layouts", () => {
  const customAttributeType = codedIndexSchemaByName("CustomAttributeType");

  assert.strictEqual(customAttributeType?.tagBits, 3);
  assert.deepStrictEqual(customAttributeType?.tables.slice(0, 5), [-1, -1, 0x06, 0x0a, -1]);
  assert.strictEqual(codedIndexSchemaByName("NoSuchCodedIndex"), null);
});

void test("metadataToken combines table id and one-based metadata row id", () => {
  assert.strictEqual(metadataToken(0x0a, 0x1234), 0x0a001234);
});
