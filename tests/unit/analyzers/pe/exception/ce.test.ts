import assert from "node:assert/strict";
import { test } from "node:test";
import { parseCeExceptionTable } from "../../../../../analyzers/pe/exception/ce.js";
import { ceExceptionRows, ceExceptionImage, ceExceptionMap, ceFunctionWord } from "../../../../fixtures/pe-ce-exception.js";
import { MockFile } from "../../../../helpers/mock-file.js";

void test("CE converts instruction counts into byte ranges and preserves shared handler metadata", async () => {
  const source = ceExceptionRows([[0x401080, ceFunctionWord(4, 1, 4, 1)],
    [0x401090, ceFunctionWord(8, 0, 2)]]);
  const parsed = await parseCeExceptionTable(ceExceptionImage(), source, source.size, ceExceptionMap, 0x400000n);

  assert.equal(parsed.format, "ce");
  assert.equal(parsed.functionCount, 2);
  assert.equal(parsed.invalidEntryCount, 0);
  assert.deepEqual(parsed.beginRvas, [0x1080, 0x1090]);
  assert.deepEqual(parsed.rangeLengths, [16, 16]);
  assert.deepEqual(parsed.handlerRvas, [0x1100]);
  assert.equal(parsed.handlerUnwindInfoCount, 1);
  assert.equal(parsed.uniqueUnwindInfoCount, 2);
  assert.deepEqual(parsed.ceCompressed, { instruction16Count: 1, instruction32Count: 1,
    extendedEntryCount: 0, handlerDataCount: 1,
    prologs: { count: 2, empty: 1, minimumBytes: 0, maximumBytes: 4 } });
  assert.deepEqual(parsed.issues, []);
});

void test("CE does not read a preceding PDATA_EH when its flag is clear", async () => {
  const file = ceExceptionImage();
  const calls: number[] = [];
  const source = ceExceptionRows([[0x401080, ceFunctionWord()]]);
  const parsed = await parseCeExceptionTable({ size: file.size,
    read: async (offset, size) => { calls.push(offset); return file.read(offset, size); },
    readBytes: (offset, size) => file.readBytes(offset, size) }, source, source.size, ceExceptionMap, 0x400000n);

  assert.equal(parsed.invalidEntryCount, 0);
  assert.equal(parsed.handlerUnwindInfoCount, 0);
  assert.deepEqual(calls, []);
  assert.equal(parsed.ceCompressed?.handlerDataCount, 0);
});

void test("CE normalizes ARM handler Thumb state, retaining data-only and empty PDATA_EH records", async () => {
  const source = ceExceptionRows([[0x401080, ceFunctionWord(4, 1, 4, 1)]]);
  const thumb = await parseCeExceptionTable(ceExceptionImage(0x401101), source, source.size,
    ceExceptionMap, 0x400000n, 0x1c2);
  const dataOnly = await parseCeExceptionTable(ceExceptionImage(0), source, source.size, ceExceptionMap, 0x400000n);
  const empty = await parseCeExceptionTable(ceExceptionImage(0, 0), source, source.size, ceExceptionMap, 0x400000n);
  const sh = await parseCeExceptionTable(ceExceptionImage(), source, source.size, ceExceptionMap, 0x400000n, 0x1a6);

  assert.deepEqual(thumb.handlerRvas, [0x1100]);
  assert.deepEqual(dataOnly.handlerRvas, []);
  assert.equal(dataOnly.ceCompressed?.handlerDataCount, 1);
  assert.deepEqual(empty.issues, []);
  assert.equal(empty.ceCompressed?.handlerDataCount, 0);
  assert.deepEqual(sh.handlerRvas, [0x1100]);
});

void test("CE diagnoses unmapped handler pointers without dropping a validated function range", async () => {
  const source = ceExceptionRows([[0x401080, ceFunctionWord(4, 1, 4, 1)]]);
  const parsed = await parseCeExceptionTable(ceExceptionImage(0x3ffffc, 0x401300), source, source.size,
    ceExceptionMap, 0x400000n);

  assert.deepEqual(parsed.beginRvas, [0x1080]);
  assert.equal(parsed.invalidEntryCount, 0);
  assert.equal(parsed.handlerUnwindInfoCount, 1);
  assert.deepEqual(parsed.handlerRvas, []);
  assert.ok(parsed.issues.includes("CE exception handler VA could not be mapped."));
  assert.ok(parsed.issues.includes("CE handler data VA could not be mapped."));
});

void test("CE bounds handler prefixes by mapped image bytes and checks underflow", async () => {
  const source = ceExceptionRows([[0x401080, ceFunctionWord(4, 1, 4, 1)]]);
  const truncated = await parseCeExceptionTable(ceExceptionImage(), source, source.size,
    rva => rva === 0x107f ? null : ceExceptionMap(rva), 0x400000n);
  const low = ceExceptionRows([[4, ceFunctionWord(1, 0, 4, 1)]]);
  const underflow = await parseCeExceptionTable(new MockFile(new Uint8Array(8)), low, low.size, rva => rva, 0n);

  assert.equal(truncated.invalidEntryCount, 0);
  assert.match(truncated.issues.join(" | "), /PDATA_EH.*truncated/);
  assert.equal(underflow.invalidEntryCount, 0);
  assert.match(underflow.issues.join(" | "), /PDATA_EH.*before.*image/);
});

void test("CE preserves valid neighboring rows when starts, lengths or prologs are malformed", async () => {
  const source = ceExceptionRows([[0x3ffffc, ceFunctionWord()], [0x401081, ceFunctionWord()],
    [0x4011fc, ceFunctionWord()], [0x401080, ceFunctionWord(4, 5)],
    [0x401040, ceFunctionWord(4, 4)]]);
  const parsed = await parseCeExceptionTable(ceExceptionImage(), source, source.size, ceExceptionMap, 0x400000n);

  assert.equal(parsed.functionCount, 5);
  assert.equal(parsed.invalidEntryCount, 3);
  assert.deepEqual(parsed.beginRvas, [0x1080, 0x1040]);
  assert.deepEqual(parsed.rangeLengths, [16, 16]);
  assert.match(parsed.issues.join(" | "), /four-byte aligned/);
  assert.match(parsed.issues.join(" | "), /prolog.*exceeds/);
  assert.match(parsed.issues.join(" | "), /not sorted/);
  assert.deepEqual(parsed.ceCompressed?.prologs, { count: 1, empty: 0, minimumBytes: 16, maximumBytes: 16 });
});

void test("CE zero-length extensions stay unresolved without guessing a range or handler layout", async () => {
  const source = ceExceptionRows([[0x401080, ceFunctionWord(0, 0, 4, 1)]]);
  const parsed = await parseCeExceptionTable(ceExceptionImage(), source, source.size, ceExceptionMap, 0x400000n);

  assert.equal(parsed.functionCount, 1);
  assert.equal(parsed.invalidEntryCount, 1);
  assert.deepEqual(parsed.beginRvas, []);
  assert.deepEqual(parsed.handlerRvas, []);
  assert.equal(parsed.handlerUnwindInfoCount, 1);
  assert.equal(parsed.ceCompressed?.extendedEntryCount, 1);
  assert.equal(parsed.ceCompressed?.prologs, undefined);
  assert.match(parsed.issues.join(" | "), /extended function-length.*not decoded/);
});

for (const base of [undefined, -1n, 0x100000000n]) {
  void test(`CE rejects missing or non-32-bit image bases: ${base}`, async () => {
    const source = ceExceptionRows([[0x401080, ceFunctionWord()]]);
    const parsed = await parseCeExceptionTable(ceExceptionImage(), source, source.size, ceExceptionMap, base);

    assert.equal(parsed.functionCount, 0);
    assert.match(parsed.issues[0]!, /ImageBase/);
  });
}

for (const size of [0, 2, -1, 8.5, NaN, Infinity]) {
  void test(`CE rejects invalid table sizes: ${size}`, async () => {
    const source = ceExceptionRows([[0x401080, ceFunctionWord()]]);
    const parsed = await parseCeExceptionTable(ceExceptionImage(), source, size, ceExceptionMap, 0x400000n);

    assert.equal(parsed.functionCount, 0);
    assert.match(parsed.issues[0]!, /size/);
  });
}

void test("CE retains complete prefixes of physically truncated and non-multiple tables", async () => {
  const source = ceExceptionRows([[0x401080, ceFunctionWord()]]);
  const truncated = await parseCeExceptionTable(ceExceptionImage(), source, 16, ceExceptionMap, 0x400000n);
  const partial = await parseCeExceptionTable(ceExceptionImage(), source, 9, ceExceptionMap, 0x400000n);
  const empty = await parseCeExceptionTable(ceExceptionImage(), new MockFile(new Uint8Array(7)), 8,
    ceExceptionMap, 0x400000n);

  assert.equal(truncated.functionCount, 1);
  assert.match(truncated.issues.join(" | "), /truncated/);
  assert.equal(partial.functionCount, 1);
  assert.match(partial.issues.join(" | "), /multiple/);
  assert.equal(empty.functionCount, 0);
  assert.equal(empty.ceCompressed, undefined);
});

void test("CE keeps duplicate starts ordered and resolves shared handlers only once", async () => {
  const source = ceExceptionRows([[0x401080, ceFunctionWord(4, 4, 4, 1)],
    [0x401080, ceFunctionWord(4, 4, 4, 1)]]);
  const parsed = await parseCeExceptionTable(ceExceptionImage(), source, source.size, ceExceptionMap, 0x400000n);

  assert.equal(parsed.functionCount, 2);
  assert.equal(parsed.handlerUnwindInfoCount, 2);
  assert.deepEqual(parsed.handlerRvas, [0x1100]);
  assert.equal(parsed.ceCompressed?.prologs?.maximumBytes, 16);
  assert.deepEqual(parsed.issues, []);
});

void test("CE supports zero image bases and handler data in mapped image headers", async () => {
  const source = ceExceptionRows([[0x1080, ceFunctionWord(4, 0, 4, 1)]]);
  const parsed = await parseCeExceptionTable(ceExceptionImage(0x1100, 0x1110), source, source.size, ceExceptionMap, 0n);
  const headerSource = ceExceptionRows([[0x401080, ceFunctionWord(4, 0, 4, 1)]]);
  const header = await parseCeExceptionTable(ceExceptionImage(0x401100, 0x400000), headerSource, headerSource.size,
    rva => rva === 0 ? 0 : ceExceptionMap(rva), 0x400000n);

  assert.deepEqual(parsed.beginRvas, [0x1080]);
  assert.deepEqual(parsed.issues, []);
  assert.equal(header.ceCompressed?.handlerDataCount, 1);
  assert.deepEqual(header.issues, []);
});

void test("CE accepts the maximum unsigned ImageBase but rejects function VAs below it", async () => {
  const source = ceExceptionRows([[0xfffffffc, ceFunctionWord()]]);
  const parsed = await parseCeExceptionTable(ceExceptionImage(), source, source.size, ceExceptionMap, 0xffffffffn);

  assert.equal(parsed.functionCount, 1);
  assert.equal(parsed.invalidEntryCount, 1);
  assert.deepEqual(parsed.beginRvas, []);
});

void test("CE distinguishes a null pointer from a Thumb code pointer whose address is zero", async () => {
  const source = ceExceptionRows([[0x1080, ceFunctionWord(4, 0, 4, 1)]]);
  const zero = await parseCeExceptionTable(ceExceptionImage(1, 0), source, source.size,
    rva => rva === 0 ? 0 : ceExceptionMap(rva), 0n);
  const outside = ceExceptionRows([[0x401080, ceFunctionWord(4, 0, 4, 1)]]);
  const invalid = await parseCeExceptionTable(ceExceptionImage(1, 0), outside, outside.size, ceExceptionMap, 0x400000n);

  assert.deepEqual(zero.handlerRvas, [0]);
  assert.deepEqual(zero.issues, []);
  assert.deepEqual(invalid.handlerRvas, []);
  assert.ok(invalid.issues.includes("CE exception handler VA could not be mapped."));
});

void test("CE does not reinterpret an odd SH handler pointer as Arm Thumb state", async () => {
  const source = ceExceptionRows([[0x401080, ceFunctionWord(4, 0, 4, 1)]]);
  const parsed = await parseCeExceptionTable(ceExceptionImage(0x401101), source, source.size,
    ceExceptionMap, 0x400000n, 0x1a6);

  assert.deepEqual(parsed.handlerRvas, []);
  assert.ok(parsed.issues.includes("CE non-Arm exception handler VA is not instruction-aligned."));
  assert.deepEqual(parsed.beginRvas, [0x1080]);
  assert.equal(parsed.ceCompressed?.handlerDataCount, 1);
});

void test("CE accepts a complete PDATA_EH beginning at the first image byte", async () => {
  const bytes = new Uint8Array(32);
  new DataView(bytes.buffer).setUint32(4, 16, true);
  const source = ceExceptionRows([[8, ceFunctionWord(1, 0, 4, 1)]]);
  const parsed = await parseCeExceptionTable(new MockFile(bytes), source, source.size, rva => rva, 0n);

  assert.deepEqual(parsed.beginRvas, [8]);
  assert.equal(parsed.ceCompressed?.handlerDataCount, 1);
  assert.deepEqual(parsed.issues, []);
});
