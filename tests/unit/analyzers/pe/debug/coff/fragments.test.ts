import assert from "node:assert/strict";
import { test } from "node:test";
import { parseCoffDebugInfo } from "../../../../../../analyzers/pe/debug/coff.js";
import { createPeRvaFragments } from "../../../../../helpers/pe-rva-fragments.js";
import { createSymbolTable, createLineNumbers, writeU32 }
  from "../../../../../fixtures/pe-coff-debug-fixtures.js";

const createPayload = () => {
  const symbols = createSymbolTable([{ name: "long_function_name", value: 0x1234,
    sectionNumber: 2, type: 0x20, storageClass: 2, auxRecords: [new Uint8Array(18)] }],
  ["long_function_name"]);
  const lines = createLineNumbers();
  const lineOffset = 32 + symbols.bytes.length;
  const bytes = new Uint8Array(lineOffset + lines.length);
  // IMAGE_COFF_SYMBOLS_HEADER: 32 bytes, symbol entries: 18 bytes, line entries: 6 bytes.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  writeU32(bytes, 0, symbols.recordCount);
  writeU32(bytes, 4, 32);
  writeU32(bytes, 8, 2);
  writeU32(bytes, 12, lineOffset);
  bytes.set(symbols.bytes, 32);
  bytes.set(lines, lineOffset);
  return { bytes, lineOffset };
};

// Split within the COFF header, symbol value, auxiliary record, and long name respectively.
for (const split of [3, 37, 51, 73]) {
  void test(`COFF debug parses fragmented headers, symbols, auxiliary records and names at ${split}`, async () => {
    const payload = createPayload();
    const fixture = createPeRvaFragments(0x1000, payload.bytes, split);
    const warnings: string[] = [];
    const result = await parseCoffDebugInfo(fixture.reader, fixture.reader.size,
      fixture.mapping, 0x1000, 0, payload.bytes.length, message => warnings.push(message));
    assert.ok(result);
    assert.equal(result.symbols[0]?.name, "long_function_name");
    assert.equal(result.symbols[0]?.value, 0x1234);
    assert.equal(result.symbols[0]?.auxiliaryRecords[0]?.kind, "function-definition");
    assert.equal(result.lineNumberBlocks[0]?.records[1]?.lineNumber, 42);
    // 32-byte header, then two 18-byte symbol records before the string table.
    assert.equal(result.symbolTableOffset, fixture.mapping(0x1020));
    assert.equal(result.stringTableOffset, fixture.mapping(0x1044));
    assert.equal(result.lineNumberBlocks[0]?.offset, fixture.mapping(0x1000 + payload.lineOffset));
    assert.deepEqual(warnings, []);
  });
}

void test("COFF line records can continue from EOF into an earlier file fragment", async () => {
  const payload = createPayload();
  const fixture = createPeRvaFragments(0x1000, payload.bytes,
    payload.lineOffset + 3, payload.bytes.length + 64, 0);
  const warnings: string[] = [];
  const result = await parseCoffDebugInfo(fixture.reader, fixture.reader.size,
    fixture.mapping, 0x1000, 0, payload.bytes.length, message => warnings.push(message));
  assert.ok(result);
  assert.equal(result.lineNumberBlocks[0]?.records[1]?.lineNumber, 42);
  assert.equal(result.lineNumberBlocks[0]?.offset, fixture.mapping(0x1000 + payload.lineOffset));
  assert.deepEqual(warnings, []);
});

void test("COFF external LVA tables use mapped reads beyond the debug header payload", async () => {
  const payload = createPayload();
  writeU32(payload.bytes, 4, 0x1020);
  writeU32(payload.bytes, 12, 0x1000 + payload.lineOffset);
  const fixture = createPeRvaFragments(0x1000, payload.bytes, 37);
  const warnings: string[] = [];
  const result = await parseCoffDebugInfo(fixture.reader, fixture.reader.size,
    fixture.mapping, 0x1000, 0, 32, message => warnings.push(message));
  assert.ok(result);
  assert.equal(result.symbols[0]?.name, "long_function_name");
  assert.equal(result.lineNumberBlocks[0]?.records[1]?.lineNumber, 42);
  assert.deepEqual(warnings, []);
});

void test("a gap after a COFF header must not turn its relative table offset into an RVA", async () => {
  const payload = createPayload();
  const fixture = createPeRvaFragments(0x1000, payload.bytes, 37);
  const warnings: string[] = [];
  assert.equal(await parseCoffDebugInfo(fixture.reader, fixture.reader.size,
    rva => rva === 0x1020 ? null : rva < 0x1000 ? rva : fixture.mapping(rva),
    0x1000, 0, payload.bytes.length, message => warnings.push(message)), null);
  assert.match(warnings.join(" "), /symbol table.*does not map/);
});
