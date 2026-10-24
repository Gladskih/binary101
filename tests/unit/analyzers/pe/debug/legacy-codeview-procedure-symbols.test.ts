import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewSymbols } from "../../../../../analyzers/pe/debug/legacy-codeview-symbols.js";
import { legacyReader, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewProcedure } from "../../../../fixtures/pe-codeview-procedures.js";

const utf8 = (name: string): number[] => [...new TextEncoder().encode(name), 0];
const pascal = (name: string): number[] => [name.length, ...new TextEncoder().encode(name)];

// Procedure record IDs and CV_PROCFLAGS bits below follow pinned Microsoft cvinfo.h.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L2769
void test("CodeView procedure variants retain exact type or ID links and stored spans", async () => {
  const records = [
    codeViewProcedure(0x0204, pascal("Local16")), codeViewProcedure(0x0205, pascal("Global16")),
    codeViewProcedure(0x100a, pascal("LocalST")), codeViewProcedure(0x100b, pascal("GlobalST")),
    codeViewProcedure(0x110f, utf8("LocalSZ")), codeViewProcedure(0x1110, utf8("GlobalSZ")),
    codeViewProcedure(0x1146, utf8("LocalID")), codeViewProcedure(0x1147, utf8("GlöbalID"))
  ];
  const bytes = records.flat();
  const warnings: string[] = [];

  const parsed = await readLegacyCodeViewSymbols(legacyReader(bytes, warnings), 0, bytes.length);

  assert.deepEqual(parsed.records, [
    { type: 0x0204, name: "Local16", procedure: { referenceKind: "typeIndex", reference: 0x1234,
      codeLength: 160, debugStart: 16, debugEnd: 144, storedLocation: { segment: 9, offset: 0x1234 },
      scopeOffsets: { parent: 16, end: 32, next: 48 }, flags: 0xd5 } },
    { type: 0x0205, name: "Global16", procedure: { referenceKind: "typeIndex", reference: 0x1234,
      codeLength: 160, debugStart: 16, debugEnd: 144, storedLocation: { segment: 9, offset: 0x1234 },
      scopeOffsets: { parent: 16, end: 32, next: 48 }, flags: 0xd5 } },
    ...[0x100a, 0x100b, 0x110f, 0x1110].map((type, index) => ({
      type, name: ["LocalST", "GlobalST", "LocalSZ", "GlobalSZ"][index],
      procedure: { referenceKind: "typeIndex", reference: 0x12345678, codeLength: 160,
        debugStart: 16, debugEnd: 144, storedLocation: { segment: 9, offset: 0x1234 },
        scopeOffsets: { parent: 16, end: 32, next: 48 }, flags: 0xd5 }
    })),
    { type: 0x1146, name: "LocalID", procedure: { referenceKind: "procedureId", reference: 0x12345678,
      codeLength: 160, debugStart: 16, debugEnd: 144, storedLocation: { segment: 9, offset: 0x1234 },
      scopeOffsets: { parent: 16, end: 32, next: 48 }, flags: 0xd5 } },
    { type: 0x1147, name: "GlöbalID", procedure: { referenceKind: "procedureId", reference: 0x12345678,
      codeLength: 160, debugStart: 16, debugEnd: 144, storedLocation: { segment: 9, offset: 0x1234 },
      scopeOffsets: { parent: 16, end: 32, next: 48 }, flags: 0xd5 } }
  ]);
  assert.deepEqual(warnings, []);
});

void test("CodeView procedure ID fields agree with unchanged cvdump output for a native object", async () => {
  // clang-cl 22.1.6 /Zi plus cvdump 14.00.23611 reported add as ID 0x1002,
  // length 0x11, segment:offset 0:0, zero debug bounds, scope links and flags 0xc0.
  const bytes = codeViewProcedure(0x1147, utf8("add"), 0x11, 0, 0, 0xc0, 0, 0);
  bytes.splice(28, 4, ...legacyU32(0x1002));
  bytes.fill(0, 4, 16);
  const warnings: string[] = [];

  const parsed = await readLegacyCodeViewSymbols(legacyReader(bytes, warnings), 0, bytes.length);

  assert.deepEqual(parsed.records, [{ type: 0x1147, name: "add", procedure: {
    referenceKind: "procedureId", reference: 0x1002, codeLength: 0x11, debugStart: 0, debugEnd: 0,
    storedLocation: { segment: 0, offset: 0 }, scopeOffsets: { parent: 0, end: 0, next: 0 }, flags: 0xc0
  } }]);
  assert.deepEqual(warnings, []);
});

void test("CodeView procedure parsing warns on truncated fixed fields and preserves known kind", async () => {
  const bytes = codeViewProcedure(0x110f, utf8("Procedure")).slice(0, 12);
  bytes[0] = bytes.length - 2;
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewSymbols(legacyReader(bytes, warnings), 0, bytes.length);

  assert.deepEqual(parsed.records, [{ type: 0x110f, procedure: { referenceKind: "typeIndex" } }]);
  assert.match(warnings.join(" "), /procedure fixed fields.*bounds/);
});

void test("CodeView procedure names can fail without discarding the fixed metadata", async () => {
  const bytes = codeViewProcedure(0x110f, [0xff, 0]);
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewSymbols(legacyReader(bytes, warnings), 0, bytes.length);

  assert.deepEqual(parsed.records[0], { type: 0x110f, procedure: { referenceKind: "typeIndex",
    reference: 0x12345678, codeLength: 160, debugStart: 16, debugEnd: 144,
    storedLocation: { segment: 9, offset: 0x1234 }, scopeOffsets: { parent: 16, end: 32, next: 48 },
    flags: 0xd5 } });
  assert.match(warnings.join(" "), /procedure name/);
});

void test("CodeView procedure debug spans are warned when reversed or beyond procedure length", async () => {
  const reversed = codeViewProcedure(0x110f, utf8("Reversed"), 80, 90, 60);
  const tooLong = codeViewProcedure(0x1110, utf8("TooLong"), 50, 30, 60);
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewSymbols(legacyReader([...reversed, ...tooLong], warnings), 0,
    reversed.length + tooLong.length);

  assert.equal(parsed.records.length, 2);
  assert.deepEqual(warnings, ["CodeView procedure debug span starts after it ends.",
    "CodeView procedure debug span exceeds the stored code length.",
    "CodeView procedure debug span exceeds the stored code length."]);
});

void test("CodeView procedure debug span may end exactly at procedure length", async () => {
  const bytes = codeViewProcedure(0x110f, utf8("AtEnd"), 50, 50, 50);
  const warnings: string[] = [];

  const parsed = await readLegacyCodeViewSymbols(legacyReader(bytes, warnings), 0, bytes.length);

  assert.equal(parsed.records[0]?.procedure?.debugStart, 50);
  assert.equal(parsed.records[0]?.procedure?.debugEnd, 50);
  assert.deepEqual(warnings, []);
});
