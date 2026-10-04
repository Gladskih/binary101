"use strict";

import assert from "node:assert/strict";
import { createReadStream, existsSync } from "node:fs";
import { stat } from "node:fs/promises";
import { createInterface } from "node:readline";
import { test } from "node:test";
import { parseClrMetadataRoot } from "../../analyzers/pe/clr/metadata-root.js";
import type { PeClrAdditionalCell, PeClrMetadataTables } from "../../analyzers/pe/clr/types.js";
import { openDiskFileRangeReader } from "../../scripts/disk-file-range-reader.js";
import { resolveClrMetadataDependencies } from "../../analyzers/pe/clr/metadata-dependencies.js";

type ReferenceAssembly = {
  path: string;
  metadataOffset: number;
  metadataSize: number;
  counts: { tableId: number; rows: number }[];
  signatures: Record<string, PeClrAdditionalCell>;
  signatureErrors?: Record<string, string>;
  blobs: {
    constants: { row: number; value: unknown }[];
    marshal: { row: number; nativeType: string; parameters: Record<string, string | number> }[];
    security: { row: number; attributes: { namedArguments: { kind: string; name: string; value: unknown }[] }[] }[];
  };
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

const compareAssembly = async (
  reference: ReferenceAssembly, dependencies: ReadonlyMap<string, PeClrMetadataTables>
): Promise<{
  signatures: number; unresolvedSecurity: number
}> => {
  const disk = await openDiskFileRangeReader(reference.path, (await stat(reference.path)).size);
  try {
    const issues: string[] = [];
    const parsed = dependencies.get(reference.path) ?? (await parseClrMetadataRoot(
      disk.reader, reference.metadataOffset,
      reference.metadataSize, issues))?.tables;
    assert.ok(parsed, `${reference.path}: missing metadata tables; ${issues.join("; ")}`);
    const tables = resolveClrMetadataDependencies(parsed, [...dependencies.values()]);
    assert.deepEqual(tables.rowCounts.map(({ tableId, rows }) => ({ tableId, rows })), reference.counts,
      `${reference.path}: table counts`);
    const signatures = collectSignatures(tables);
    assert.equal(signatures.size, Object.keys(reference.signatures).length +
      Object.keys(reference.signatureErrors ?? {}).length, `${reference.path}: signature count`);
    for (const [key, expected] of Object.entries(reference.signatures)) {
      assert.deepEqual(signatures.get(key), expected, `${reference.path}: signature ${key}`);
    }
    for (const key of Object.keys(reference.signatureErrors ?? {})) {
      const signature = signatures.get(key);
      assert.ok(signature && typeof signature === "object" && "issues" in signature && signature.issues?.length,
        `${reference.path}: rejected reference signature ${key} must report a warning`);
    }
    compareAttributes(reference, tables);
    return { signatures: signatures.size, unresolvedSecurity: compareBlobs(reference, tables) };
  } finally {
    await disk.close();
  }
};

const compareBlobs = (reference: ReferenceAssembly, tables: PeClrMetadataTables): number => {
  for (const expected of reference.blobs.constants) {
    const actual = tables.additionalTables?.find(table => table.tableId === 0x0b)?.rows[expected.row - 1]?.["Value"];
    assert.ok(actual && typeof actual === "object" && "kind" in actual && actual.kind === "constant");
    assert.deepEqual(normalizeConstant(actual.value, expected.value), expected.value,
      `${reference.path}: constant ${expected.row}`);
    assert.equal(actual.issues, undefined, `${reference.path}: constant ${expected.row} warnings`);
  }
  for (const expected of reference.blobs.marshal) {
    const actual = tables.additionalTables?.find(table => table.tableId === 0x0d)?.rows[expected.row - 1]?.["NativeType"];
    assert.ok(actual && typeof actual === "object" && "kind" in actual && actual.kind === "marshal");
    assert.equal(actual.nativeType === "INTERFACE" ? "INTF" : actual.nativeType, expected.nativeType,
      `${reference.path}: marshal ${expected.row} type`);
    assert.deepEqual({ ...actual.parameters,
      ...(typeof actual.parameters["marshalerType"] === "string"
        ? { marshalerType: actual.parameters["marshalerType"].split(",")[0] } : {}) }, expected.parameters,
      `${reference.path}: marshal ${expected.row} parameters`);
    assert.equal(actual.issues, undefined, `${reference.path}: marshal ${expected.row} warnings`);
  }
  return compareSecurity(reference, tables);
};

const normalizeConstant = (actual: unknown, expected: unknown): unknown => {
  if (expected && typeof expected === "object" && "utf16" in expected && typeof actual === "string") {
    return { utf16: actual.split("").map(unit => unit.charCodeAt(0)) };
  }
  return typeof actual === "number" && !Number.isFinite(actual) ? String(actual) : actual;
};

const compareSecurity = (reference: ReferenceAssembly, tables: PeClrMetadataTables): number => {
  let unresolved = 0;
  for (const expected of reference.blobs.security) {
    const actual = tables.additionalTables?.find(table => table.tableId === 0x0e)?.rows[expected.row - 1]?.["PermissionSet"];
    assert.ok(actual && typeof actual === "object" && "kind" in actual && actual.kind === "security"
      && actual.encoding === "binary");
    if (actual.attributes.some(attribute => attribute.issues?.some(issue => /underlying type is unresolved/.test(issue)))) {
      // Missing selected dependencies remain visible and are counted separately.
      unresolved += 1;
      continue;
    }
    assert.deepEqual(actual.attributes.map(attribute => ({ namedArguments:
      attribute.namedArguments.map(({ kind, name, value }) => ({ kind, name, value })) })), expected.attributes,
      `${reference.path}: security ${expected.row}`);
    assert.equal(actual.issues, undefined, `${reference.path}: security ${expected.row} warnings`);
  }
  return unresolved;
};

const compareAttributes = (reference: ReferenceAssembly, tables: PeClrMetadataTables): void => {
  for (const expected of reference.attributes) {
    const actual = tables.customAttributes[expected.row - 1];
    assert.ok(actual, `${reference.path}: missing attribute ${expected.row}`);
    assert.deepEqual(actual.fixedArguments.map(argument => normalizeConstant(argument.value, null)),
      expected.fixedArguments,
      `${reference.path}: attribute ${expected.row} fixed arguments; ${actual.issues?.join("; ") ?? ""}`);
    assert.deepEqual(actual.namedArguments.map(({ kind, name, value }) => ({ kind, name,
      value: normalizeConstant(value, null) })),
      expected.namedArguments, `${reference.path}: attribute ${expected.row} named arguments`);
    assert.equal(actual.issues, undefined, `${reference.path}: attribute ${expected.row} issues`);
  }
};

const compareCorpus = async (manifest: string): Promise<{
  assemblies: number; signatures: number; attributes: number;
  constants: number; marshal: number; security: number; unresolvedSecurity: number
}> => {
  const dependencies = await readDependencies(manifest);
  const lines = createInterface({ input: createReadStream(manifest), crlfDelay: Infinity });
  let assemblies = 0;
  let signatures = 0;
  let attributes = 0;
  let constants = 0;
  let marshal = 0;
  let security = 0;
  let unresolvedSecurity = 0;
  for await (const line of lines) {
    const reference = JSON.parse(line) as ReferenceAssembly;
    const checked = await compareAssembly(reference, dependencies);
    signatures += checked.signatures;
    unresolvedSecurity += checked.unresolvedSecurity;
    attributes += reference.attributes.length;
    constants += reference.blobs.constants.length;
    marshal += reference.blobs.marshal.length;
    security += reference.blobs.security.length - checked.unresolvedSecurity;
    assemblies += 1;
  }
  assert.ok(assemblies > 0, "Reference corpus is empty");
  return { assemblies, signatures, attributes, constants, marshal, security, unresolvedSecurity };
};

const readDependencies = async (manifest: string): Promise<ReadonlyMap<string, PeClrMetadataTables>> => {
  const dependencies = new Map<string, PeClrMetadataTables>();
  const lines = createInterface({ input: createReadStream(manifest), crlfDelay: Infinity });
  for await (const line of lines) {
    const reference = JSON.parse(line) as ReferenceAssembly;
    if (!/[\\/]Framework64[\\/].*[\\/](mscorlib|System)\.dll$/i.test(reference.path) &&
      !/[\\/]GAC_MSIL[\\/]System\.Drawing[\\/].*[\\/]System\.Drawing\.dll$/i.test(reference.path) &&
      !/[\\/]Microsoft\.NETCore\.App[\\/].*[\\/](System\.Private\.CoreLib|System\.Runtime)\.dll$/i
        .test(reference.path)) continue;
    const disk = await openDiskFileRangeReader(reference.path, (await stat(reference.path)).size);
    try {
      const tables = (await parseClrMetadataRoot(
        disk.reader, reference.metadataOffset, reference.metadataSize, []))?.tables;
      assert.ok(tables);
      dependencies.set(reference.path, tables);
    } finally { await disk.close(); }
  }
  return dependencies;
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
