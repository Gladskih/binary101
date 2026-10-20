import assert from "node:assert/strict";
import { test } from "node:test";
import { resolvePortablePdbConstantValue, resolveDebugConstants } from "../../../../../analyzers/pe/debug/portable-pdb-constant-values.js";
import type { PortablePdbConstant } from "../../../../../analyzers/pe/debug/portable-pdb-constants.js";
import { createClrMetadataTablesWithParameterNames } from "../../../../fixtures/pe-clr-metadata-tables.js";
import { createDebugViewEntry } from "../../../../fixtures/pe-debug-view-subject.js";
import { parsePortablePdb } from "../../../../../analyzers/pe/debug/portable-pdb.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { createPortablePdbRoot, createPortablePdbStreams } from "../../../../fixtures/portable-pdb.js";

void test("Portable PDB resolves Decimal only after its CLR type is established", () => {
  const value: PortablePdbConstant = { typeCode: 17, typeReference: { tableId: 1, row: 1 },
    data: [130, 210, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }; // Negative, scale 2, magnitude 1234.
  const issues: string[] = [];

  assert.deepEqual(resolvePortablePdbConstantValue(value, "System.Decimal", issues),
    { typeCode: 17, typeReference: { tableId: 1, row: 1 }, value: "-12.34" });
  assert.equal(resolvePortablePdbConstantValue(value, "Example.Decimal", issues), value);
  assert.equal(resolvePortablePdbConstantValue(value, null, issues), value);
  assert.deepEqual(issues, []);
});

void test("Portable PDB preserves full Decimal precision, scale and leading fractional zeroes", () => {
  const issues: string[] = [];

  assert.equal(resolvePortablePdbConstantValue({ typeCode: 17,
    data: [0, ...new Array<number>(12).fill(255)] }, "System.Decimal", issues).value,
  "79228162514264337593543950335");
  assert.equal(resolvePortablePdbConstantValue({ typeCode: 17,
    data: [3, 1, ...new Array<number>(11).fill(0)] }, "System.Decimal", issues).value, "0.001");
  assert.equal(resolvePortablePdbConstantValue({ typeCode: 17,
    data: [128, ...new Array<number>(12).fill(0)] }, "System.Decimal", issues).value, "0");
  assert.deepEqual(issues, []);
});

void test("Portable PDB DateTime ticks retain seven fractional digits without inventing a time zone", () => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigInt64(0, 621355968000000001n, true); // Unix epoch plus one 100 ns tick.
  const issues: string[] = [];

  assert.equal(resolvePortablePdbConstantValue({ typeCode: 17, data: [...bytes] },
    "System.DateTime", issues).value, "1970-01-01T00:00:00.0000001");
  assert.deepEqual(issues, []);
});

void test("Portable PDB keeps opaque/default constants and reports malformed special values", () => {
  const primitive: PortablePdbConstant = { typeCode: 8, value: 3 };
  const defaultValue: PortablePdbConstant = { typeCode: 18, data: [] };
  const issues: string[] = [];

  assert.equal(resolvePortablePdbConstantValue(primitive, "System.Decimal", issues), primitive);
  assert.equal(resolvePortablePdbConstantValue(defaultValue, "System.Decimal", issues), defaultValue);
  assert.deepEqual(resolvePortablePdbConstantValue({ typeCode: 17, data: [29, ...new Array<number>(12).fill(0)] },
    "System.Decimal", issues).data, [29, ...new Array<number>(12).fill(0)]);
  assert.deepEqual(resolvePortablePdbConstantValue({ typeCode: 17, data: [0] }, "System.DateTime", issues).data, [0]);
  assert.deepEqual(resolvePortablePdbConstantValue({ typeCode: 17, data: [0] }, "System.Decimal", issues).data, [0]);
  assert.deepEqual(resolvePortablePdbConstantValue({ typeCode: 17, data: new Array<number>(8).fill(255) },
    "System.DateTime", issues).data, new Array<number>(8).fill(255));
  assert.ok(issues.length >= 3);
});

void test("Portable PDB constant linking caches shared values and preserves visible diagnostics", async () => {
  const metadata = createClrMetadataTablesWithParameterNames();
  metadata.typeDefs[0]!.fullName = "System.Decimal";
  const pdb = (await parsePortablePdb(new MockFile(createPortablePdbRoot(createPortablePdbStreams())), []))!;
  const constant: PortablePdbConstant = { typeCode: 17, typeReference: { tableId: 2, row: 1 }, data: [0] };
  pdb.locals.push({ kind: "constant", name: "invalid", signatureSize: 2, constant },
    { kind: "constant", name: "alias", signatureSize: 2, constant },
    { kind: "constant", name: "unreadable", signatureSize: null, constant: null });
  const debug = { entry: null, warning: "Previous warning.", entries: [
    { ...createDebugViewEntry(17, 0, 128), embeddedPortablePdb: {
      signature: "MPDB", compressedSize: 8, uncompressedSize: 32, portablePdb: pdb
    } }, createDebugViewEntry(2, 0, 128)
  ] };

  const result = resolveDebugConstants(debug, metadata);

  assert.match(result?.warning ?? "", /Previous warning/);
  assert.equal(result?.warning?.match(/13 bytes/g)?.length, 1);
  assert.equal(debug.warning, "Previous warning.");
  assert.equal(result?.entries?.[1], debug.entries[1]);
});

void test("Portable PDB constant linking handles missing debug metadata and unresolved types", async () => {
  const metadata = createClrMetadataTablesWithParameterNames();
  const pdb = await parsePortablePdb(new MockFile(createPortablePdbRoot(createPortablePdbStreams())), []);
  pdb!.locals = [{ kind: "constant", name: "unresolved", signatureSize: 2,
    constant: { typeCode: 17, data: [0], typeReference: { tableId: 0x1b, row: 1 } } }];
  const debug = { entry: null, entries: [{ ...createDebugViewEntry(17, 0, 128), embeddedPortablePdb: {
    signature: "MPDB", compressedSize: 8, uncompressedSize: 32, portablePdb: pdb!
  } }] };

  assert.equal(resolveDebugConstants(null, metadata), null);
  assert.equal(resolveDebugConstants(debug, undefined), debug);
  assert.deepEqual(resolveDebugConstants({ entry: null }, metadata), { entry: null });
  assert.deepEqual(resolveDebugConstants(debug, metadata)?.entries?.[0]?.embeddedPortablePdb?.portablePdb?.locals,
    pdb!.locals);
});
