"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseMetadataTableStream } from "../../analyzers/pe/clr/metadata-table-reader.js";

const TABLE_MODULE = 0x00; // ECMA-335 II.22.30 Module table id.
const TABLE_TYPE_DEF = 0x02; // ECMA-335 II.22.37 TypeDef table id.
const TABLE_CUSTOM_ATTRIBUTE = 0x0c; // ECMA-335 II.22.10 CustomAttribute table id.
const ALL_HEAP_INDEXES_WIDE = 0x07; // ECMA-335 II.24.2.6 HeapSizes bits for 4-byte indexes.
const HEAP_EXTRA_DATA = 0x40; // CoreCLR CMiniMdSchemaBase::EXTRA_DATA schema flag.
const READY_TO_RUN_LARGEST_RID_LOG2 = 0x0a; // Observed in CoreCLR ReadyToRun table streams.
const UNKNOWN_HEAP_SCHEMA_FLAG = 0x10; // Not defined by ECMA-335 II.24.2.6 or CMiniMdSchemaBase.
const SCHEMA_EXTRA_DATA_SENTINEL = 0x12345678; // Distinct test value for parsed ExtraData.

class TableBytes {
  readonly bytes: number[] = [];

  u8(value: number): this {
    this.bytes.push(value & 0xff);
    return this;
  }

  u16(value: number): this {
    this.bytes.push(value & 0xff, (value >>> 8) & 0xff);
    return this;
  }

  u32(value: number): this {
    this.bytes.push(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
    return this;
  }

  u64(value: bigint): this {
    this.u32(Number(value & 0xffffffffn));
    this.u32(Number((value >> 32n) & 0xffffffffn));
    return this;
  }
}

const tableMask = (...tableIds: number[]): bigint =>
  tableIds.reduce((mask, tableId) => mask | (1n << BigInt(tableId)), 0n);

const createTableStream = (
  validMask: bigint,
  rowCounts: number[],
  rowBytes: number[],
  heapSizes = 0,
  largestRidLog2 = 0,
  extraData?: number
): Uint8Array => {
  const writer = new TableBytes();
  writer.u32(0).u8(2).u8(0).u8(heapSizes).u8(largestRidLog2).u64(validMask).u64(0n);
  rowCounts.forEach(rowCount => writer.u32(rowCount));
  if (extraData != null) writer.u32(extraData);
  writer.bytes.push(...rowBytes);
  return Uint8Array.from(writer.bytes);
};

void test("parseMetadataTableStream decodes wide heap indexes and Module rows", () => {
  const row = new TableBytes()
    .u16(0)
    .u32(0x12345)
    .u32(1)
    .u32(0)
    .u32(0)
    .bytes;
  const issues: string[] = [];
  const parsed = parseMetadataTableStream(
    createTableStream(tableMask(TABLE_MODULE), [1], row, ALL_HEAP_INDEXES_WIDE),
    "#~",
    issues
  );
  const moduleRow = parsed?.tables.get(TABLE_MODULE)?.rows[0];

  assert.strictEqual(parsed?.heapIndexSizes.string, 4);
  assert.strictEqual(moduleRow?.["Name"], 0x12345);
  assert.strictEqual(moduleRow?.["Mvid"], 1);
  assert.deepStrictEqual(issues, []);
});

void test("parseMetadataTableStream accepts CoreCLR RID log byte", () => {
  const row = new TableBytes()
    .u16(0)
    .u16(1)
    .u16(1)
    .u16(0)
    .u16(0)
    .bytes;
  const issues: string[] = [];
  const parsed = parseMetadataTableStream(
    createTableStream(tableMask(TABLE_MODULE), [1], row, 0, READY_TO_RUN_LARGEST_RID_LOG2),
    "#~",
    issues
  );

  assert.strictEqual(parsed?.largestRidLog2, READY_TO_RUN_LARGEST_RID_LOG2);
  assert.deepStrictEqual(issues, []);
});

void test("parseMetadataTableStream skips CoreCLR extra schema data before table rows", () => {
  const row = new TableBytes()
    .u16(0)
    .u16(1)
    .u16(1)
    .u16(0)
    .u16(0)
    .bytes;
  const issues: string[] = [];
  const parsed = parseMetadataTableStream(
    createTableStream(tableMask(TABLE_MODULE), [1], row, HEAP_EXTRA_DATA, 0, SCHEMA_EXTRA_DATA_SENTINEL),
    "#~",
    issues
  );
  const moduleRow = parsed?.tables.get(TABLE_MODULE)?.rows[0];

  assert.strictEqual(parsed?.extraData, SCHEMA_EXTRA_DATA_SENTINEL);
  assert.strictEqual(moduleRow?.["Name"], 1);
  assert.deepStrictEqual(issues, []);
});

void test("parseMetadataTableStream reports unknown heap schema flags", () => {
  const issues: string[] = [];
  parseMetadataTableStream(
    createTableStream(tableMask(TABLE_MODULE), [1], [], UNKNOWN_HEAP_SCHEMA_FLAG),
    "#~",
    issues
  );

  assert.ok(issues.some(issue => /unknown CoreCLR schema flag bits/i.test(issue)));
});

void test("parseMetadataTableStream reports reserved coded-index tags", () => {
  const row = new TableBytes()
    .u16(0)
    .u16(1)
    .u16(0)
    .bytes;
  const issues: string[] = [];
  const parsed = parseMetadataTableStream(
    createTableStream(tableMask(TABLE_CUSTOM_ATTRIBUTE), [1], row),
    "#~",
    issues
  );
  const typeIndex = parsed?.tables.get(TABLE_CUSTOM_ATTRIBUTE)?.rows[0]?.["Type"];

  assert.strictEqual(typeof typeIndex, "object");
  assert.ok(issues.some(issue => /reserved tag/i.test(issue)));
});

void test("parseMetadataTableStream keeps invalid table indexes visible", () => {
  const row = new TableBytes()
    .u32(0)
    .u16(0)
    .u16(0)
    .u16(0)
    .u16(0)
    .u16(1)
    .bytes;
  const issues: string[] = [];
  const parsed = parseMetadataTableStream(
    createTableStream(tableMask(TABLE_TYPE_DEF), [1], row),
    "#~",
    issues
  );
  const methodList = parsed?.tables.get(TABLE_TYPE_DEF)?.rows[0]?.["MethodList"];

  assert.strictEqual(typeof methodList, "object");
  if (typeof methodList === "object") assert.strictEqual(methodList.valid, false);
  assert.deepStrictEqual(issues, []);
});

void test("parseMetadataTableStream reports truncated and unsupported table streams", () => {
  const truncatedIssues: string[] = [];
  assert.strictEqual(parseMetadataTableStream(Uint8Array.of(1, 2, 3), "#~", truncatedIssues), null);
  assert.ok(truncatedIssues.some(issue => /smaller/i.test(issue)));

  const unsupportedIssues: string[] = [];
  parseMetadataTableStream(createTableStream(tableMask(0x3f), [1], []), "#~", unsupportedIssues);
  assert.ok(unsupportedIssues.some(issue => /unsupported/i.test(issue)));
});
