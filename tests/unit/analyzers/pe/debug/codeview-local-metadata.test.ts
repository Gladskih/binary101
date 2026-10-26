import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewSymbolText } from "../../../../../analyzers/pe/debug/legacy-codeview-symbol-text.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { frameRecord, localVariableRecord, localRecord, localRangeBytes,
  localName } from "../../../../fixtures/pe-codeview-locals.js";

void test("CodeView symbol dispatch retains frame metadata instead of just its record kind", async () => {
  const result = await readLegacyCodeViewSymbolText(legacyReader(frameRecord()), 0x1012);

  assert.deepEqual(result, { frame: { frameBytes: 64, paddingBytes: 8, paddingOffset: 24,
    savedRegisterBytes: 16, handler: { offset: 0x1234, section: 3 }, flags: 0 } });
});

void test("CodeView symbol dispatch retains the name, type and flags of optimized locals", async () => {
  const result = await readLegacyCodeViewSymbolText(legacyReader(localVariableRecord("<value>&amp;", 0x101)), 0x113e);

  assert.deepEqual(result, { name: "<value>&amp;", local: { typeIndex: 0x1001, flags: 0x101 } });
});

void test("CodeView symbol dispatch retains register ranges and gaps", async () => {
  const bytes = localRecord(0x1141, [...legacyU16(328), ...legacyU16(1), ...localRangeBytes(),
    ...legacyU16(4), ...legacyU16(8)]);
  const result = await readLegacyCodeViewSymbolText(legacyReader(bytes), 0x1141);

  assert.deepEqual(result, { localRange: { location: { kind: "register", register: 328 }, attributes: 1,
    range: { offset: 32, section: 1, length: 32 }, gaps: [{ offset: 4, length: 8 }] } });
});

void test("CodeView symbol dispatch retains attributed register lists and contains truncated arrays", async () => {
  const result = await readLegacyCodeViewSymbolText(legacyReader(localRecord(0x1131, [...legacyU32(0x1234),
    ...legacyU32(32), ...legacyU16(1), ...legacyU16(3), ...legacyU16(2), ...legacyU16(328),
    ...legacyU16(329), ...localName("pair")])), 0x1131);
  assert.deepEqual(result, { name: "pair", local: { typeIndex: 0x1234, firstLiveAddress: { offset: 32, section: 1 },
    flags: 3, location: { kind: "registers", registers: [328, 329] } } });
  const warnings: string[] = [];
  assert.deepEqual(await readLegacyCodeViewSymbolText(legacyReader(localRecord(0x1131,
    [...legacyU32(1), ...legacyU32(0), ...legacyU16(1), ...legacyU16(0), ...legacyU16(0xffff)]), warnings),
  0x1131), {});
  assert.match(warnings.join(" | "), /metadata.*bounds/);
});

void test("CodeView 2005 local and range enums do not imply an invented body layout", async () => {
  assert.deepEqual(await readLegacyCodeViewSymbolText(legacyReader(localRecord(0x1133, [])), 0x1133), {});
  assert.deepEqual(await readLegacyCodeViewSymbolText(legacyReader(localRecord(0x1134, [])), 0x1134), {});
});

void test("CodeView dispatch contains incomplete indirect register metadata", async () => {
  const warnings: string[] = [];
  assert.deepEqual(await readLegacyCodeViewSymbolText(legacyReader(localRecord(0x1171, []), warnings), 0x1171), {});
  assert.deepEqual(await readLegacyCodeViewSymbolText(legacyReader(localRecord(0x1177, []), warnings), 0x1177), {});
  assert.equal(warnings.length, 2);
  assert.match(warnings.join(" | "), /metadata.*bounds/);
});
