"use strict";

import assert from "node:assert/strict";
import { createReadStream, existsSync } from "node:fs";
import { stat } from "node:fs/promises";
import { createInterface } from "node:readline";
import { test } from "node:test";
import { parseClrMetadataRoot } from "../../analyzers/pe/clr/metadata-root.js";
import type { PeClrAdditionalCell, PeClrMetadataTables } from "../../analyzers/pe/clr/types.js";
import { openDiskFileRangeReader } from "../../scripts/disk-file-range-reader.js";

type ReferenceAssembly = {
  path: string;
  metadataOffset: number;
  metadataSize: number;
  counts: { tableId: number; rows: number }[];
  signatures: Record<string, PeClrAdditionalCell>;
  attributes: {
    row: number;
    fixedArguments: Array<string | number | boolean | null>;
    namedArguments: { kind: string; name: string | null; value: string | number | boolean | null }[];
  }[];
};

const collectSignatures = (tables: PeClrMetadataTables): Map<string, PeClrAdditionalCell> => {
  const signatures = new Map<string, PeClrAdditionalCell>();
  // ECMA-335 II.22 table ids, independent of the production schema constants.
  for (const [tableId, rows] of [
    [4, tables.fields ?? []], [6, tables.methodDefs], [10, tables.memberRefs]
  ] as const) {
    for (const row of rows) if (row.signature) signatures.set(`${tableId}:${row.row}`, row.signature);
  }
  for (const table of tables.additionalTables ?? []) {
    if (![0x11, 0x17, 0x1b, 0x2b].includes(table.tableId)) continue;
    table.rows.forEach((row, index) => signatures.set(`${table.tableId}:${index + 1}`,
      row["Signature"] ?? row["Type"] ?? row["Instantiation"] ?? null));
  }
  return signatures;
};

const compareAssembly = async (reference: ReferenceAssembly): Promise<number> => {
  const disk = await openDiskFileRangeReader(reference.path, (await stat(reference.path)).size);
  try {
    const issues: string[] = [];
    const tables = (await parseClrMetadataRoot(disk.reader, reference.metadataOffset,
      reference.metadataSize, issues))?.tables;
    assert.ok(tables, `${reference.path}: missing metadata tables; ${issues.join("; ")}`);
    assert.deepEqual(tables.rowCounts.map(({ tableId, rows }) => ({ tableId, rows })), reference.counts,
      `${reference.path}: table counts`);
    const signatures = collectSignatures(tables);
    assert.equal(signatures.size, Object.keys(reference.signatures).length, `${reference.path}: signature count`);
    for (const [key, expected] of Object.entries(reference.signatures)) {
      assert.deepEqual(signatures.get(key), expected, `${reference.path}: signature ${key}`);
    }
    compareAttributes(reference, tables);
    return signatures.size;
  } finally {
    await disk.close();
  }
};

const compareAttributes = (reference: ReferenceAssembly, tables: PeClrMetadataTables): void => {
  for (const expected of reference.attributes) {
    const actual = tables.customAttributes[expected.row - 1];
    assert.ok(actual, `${reference.path}: missing attribute ${expected.row}`);
    assert.deepEqual(actual.fixedArguments.map(argument => argument.value), expected.fixedArguments,
      `${reference.path}: attribute ${expected.row} fixed arguments; ${actual.issues?.join("; ") ?? ""}`);
    assert.deepEqual(actual.namedArguments.map(({ kind, name, value }) => ({ kind, name, value })),
      expected.namedArguments, `${reference.path}: attribute ${expected.row} named arguments`);
    assert.equal(actual.issues, undefined, `${reference.path}: attribute ${expected.row} issues`);
  }
};

const compareCorpus = async (manifest: string): Promise<{
  assemblies: number; signatures: number; attributes: number
}> => {
  const lines = createInterface({ input: createReadStream(manifest), crlfDelay: Infinity });
  let assemblies = 0;
  let signatures = 0;
  let attributes = 0;
  for await (const line of lines) {
    const reference = JSON.parse(line) as ReferenceAssembly;
    signatures += await compareAssembly(reference);
    attributes += reference.attributes.length;
    assemblies += 1;
  }
  assert.ok(assemblies > 0, "Reference corpus is empty");
  return { assemblies, signatures, attributes };
};

void test("matches System.Reflection.Metadata on installed assemblies", {
  skip: !existsSync(process.env["BINARY101_DOTNET_REFERENCE"] ?? "test-results/dotnet-reference.jsonl")
}, async context => {
  context.diagnostic(JSON.stringify(await compareCorpus(
    process.env["BINARY101_DOTNET_REFERENCE"] ?? "test-results/dotnet-reference.jsonl"
  )));
});

const checkTruncatedAssembly = async (manifest: string): Promise<void> => {
  const lines = createInterface({ input: createReadStream(manifest), crlfDelay: Infinity });
  const first = await lines[Symbol.asyncIterator]().next();
  lines.close();
  assert.equal(first.done, false);
  const reference = JSON.parse(first.value as string) as ReferenceAssembly;
  const disk = await openDiskFileRangeReader(reference.path, (await stat(reference.path)).size);
  try {
    for (const prefix of [0, 23, 24, 64, Math.floor(reference.metadataSize / 2), reference.metadataSize - 1]) {
      const issues: string[] = [];
      await parseClrMetadataRoot({ ...disk.reader, size: reference.metadataOffset + prefix },
        reference.metadataOffset, reference.metadataSize, issues);
      assert.ok(issues.length > 0, `Real metadata truncated to ${prefix} bytes must report a warning`);
    }
  } finally {
    await disk.close();
  }
};

void test("reports truncation of real metadata without throwing", {
  skip: !existsSync(process.env["BINARY101_DOTNET_REFERENCE"] ?? "test-results/dotnet-reference.jsonl")
}, async () => {
  await checkTruncatedAssembly(process.env["BINARY101_DOTNET_REFERENCE"] ?? "test-results/dotnet-reference.jsonl");
});
