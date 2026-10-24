import assert from "node:assert/strict";
import { test } from "node:test";
import { createArmntUnwindInfoReader } from "../../../../../analyzers/pe/exception/armnt-unwind-info.js";
import { armntPackedWord, createArmntXdata } from "../../../../fixtures/pe-armnt-unwind.js";
import { MockFile } from "../../../../helpers/mock-file.js";

for (const flag of [1, 2]) {
  void test(`ARMNT decodes packed unwind flag ${flag} with 2-byte length units`, async () => {
    const issues: string[] = [];
    const info = await createArmntUnwindInfoReader(
      new MockFile(new Uint8Array(0)), () => null)(armntPackedWord(4094, flag), issues);

    assert.deepEqual(info, { functionLengthBytes: 4094, handlerRva: null,
      hasHandler: false, fragment: flag === 2, version: null });
    assert.deepEqual(issues, []);
  });
}

for (const [word, expected] of [[3, "reserved"], [5, "POP PC"],
  [armntPackedWord() | (1 << 21), "saving LR"],
  [(armntPackedWord() & ~(1 << 19)) | (1 << 20) | (1 << 21), "r11"]] as const) {
  void test(`ARMNT diagnoses unsupported packed data: ${expected}`, async () => {
    const issues: string[] = [];

    assert.equal(await createArmntUnwindInfoReader(new MockFile(new Uint8Array(0)), () => null)(word, issues), null);
    assert.ok(issues.some(issue => issue.includes(expected)));
  });
}

void test("ARMNT caches shared xdata and keeps its fragment flag", async context => {
  // F=bit22; Code Words=bits28..31. One instruction unit is two bytes.
  const file = createArmntXdata(2 | (1 << 22) | (1 << 28), 16);
  const calls = context.mock.method(file, "read");
  const read = createArmntUnwindInfoReader(file, rva => rva);
  const issues: string[] = [];
  const info = await read(8, issues);

  assert.deepEqual(info, { functionLengthBytes: 4, handlerRva: null,
    hasHandler: false, fragment: true, version: 0, opcodes: {
      opcodeCounts: {}, instructionCount: 0, complete: true, stackAdjustments: [],
      integerRegisterPopCount: 0, floatingRegisterPopCount: 0, framePointerRestores: 0,
      returnAddressLoads: 0, specialMarkers: {}, unknownOpcodeCount: 0
    } });
  assert.equal(await read(8, issues), info);
  assert.equal(calls.mock.callCount(), 2);
  assert.deepEqual(issues, []);
});

void test("ARMNT xdata preserves a complete function without a fragment flag", async () => {
  const issues: string[] = [];
  const info = await createArmntUnwindInfoReader(createArmntXdata(2 | (1 << 28), 16), rva => rva)(8, issues);

  assert.equal(info?.fragment, false);
  assert.deepEqual(issues, []);
});

void test("ARMNT reserved flag 3 never reinterprets the other bits as packed data", async () => {
  const issues: string[] = [];

  assert.equal(await createArmntUnwindInfoReader(
    new MockFile(new Uint8Array(0)), () => null)(armntPackedWord(4, 3), issues), null);
  assert.deepEqual(issues, ["ARMNT .pdata entry uses reserved unwind flag 3."]);
});

for (const [scopeBits, size] of [[2 << 23, 28], [(2 << 23) | (1 << 21), 20]] as const) {
  void test(`ARMNT locates handler data after scopes or a packed epilog: ${scopeBits}`, async () => {
    const file = createArmntXdata(2 | (1 << 20) | (1 << 28) | scopeBits, size, 0, 101);
    const issues: string[] = [];
    const info = await createArmntUnwindInfoReader(file, rva => rva)(8, issues);

    assert.equal(info?.handlerRva, 101);
    assert.equal(info?.hasHandler, true);
    assert.deepEqual(issues, []);
  });
}

void test("ARMNT reads the extension's 16-bit scope count and 8-bit code-word count", async () => {
  const file = createArmntXdata(2 | (1 << 20), 36, 2 | (2 << 16), 101);
  const issues: string[] = [];
  const info = await createArmntUnwindInfoReader(file, rva => rva)(8, issues);

  assert.equal(info?.handlerRva, 101);
  assert.deepEqual(issues, []);
});

for (const [word, size, header, expected] of [[0, 16, 0, "RVA 0"],
  [8, 10, 0, "header is truncated"], [8, 12, 0, "extended header is truncated"],
  [8, 16, 2 << 28, "record is truncated"]] as const) {
  void test(`ARMNT diagnoses missing xdata bytes: ${expected}`, async () => {
    const file = createArmntXdata(header, size);
    const issues: string[] = [];

    assert.equal(await createArmntUnwindInfoReader(file, rva => rva)(word, issues), null);
    assert.ok(issues.some(issue => issue.includes(expected)));
  });
}

for (const offset of [null, -1, 0.5, NaN, Infinity, 16]) {
  void test(`ARMNT rejects unmapped xdata at file offset ${offset}`, async () => {
    const issues: string[] = [];
    const read = createArmntUnwindInfoReader(new MockFile(new Uint8Array(16)), () => offset);

    assert.equal(await read(8, issues), null);
    assert.match(issues[0]!, /does not map/);
  });
}

void test("ARMNT caches unreadable records and retains warnings for every reference", async context => {
  const map = context.mock.fn(() => null);
  const read = createArmntUnwindInfoReader(new MockFile(new Uint8Array(16)), map);
  const issues: string[] = [];

  assert.equal(await read(8, issues), null);
  assert.equal(await read(8, issues), null);
  assert.equal(map.mock.callCount(), 1);
  assert.equal(issues.length, 2);
});

void test("ARMNT exposes reserved xdata versions as a warning", async () => {
  const issues: string[] = [];
  const info = await createArmntUnwindInfoReader(createArmntXdata(2 | (1 << 18) | (1 << 28), 16),
    rva => rva)(8, issues);

  assert.equal(info?.version, 1);
  assert.match(issues[0]!, /reserved version/);
});

void test("ARMNT xdata supports a header at physical offset zero", async () => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setUint32(0, 2 | (1 << 28), true);
  bytes.fill(0xff, 4);
  const issues: string[] = [];
  const info = await createArmntUnwindInfoReader(new MockFile(bytes), rva => rva - 8)(8, issues);

  assert.equal(info?.functionLengthBytes, 4);
  assert.deepEqual(issues, []);
});

void test("ARMNT xdata reports reserved extension bits", async () => {
  const issues: string[] = [];
  const info = await createArmntUnwindInfoReader(createArmntXdata(2, 16, 1 << 24), rva => rva)(8, issues);

  assert.equal(info?.functionLengthBytes, 4);
  assert.deepEqual(issues, ["ARMNT .xdata extended header sets reserved bits."]);
});

void test("ARMNT xdata reports a zero handler while preserving its declaration", async () => {
  const issues: string[] = [];
  const info = await createArmntUnwindInfoReader(createArmntXdata(2 | (1 << 20) | (1 << 28), 20),
    rva => rva)(8, issues);

  assert.equal(info?.hasHandler, true);
  assert.equal(info?.handlerRva, 0);
  assert.deepEqual(issues, ["ARMNT .xdata declares exception data with handler RVA 0."]);
});

void test("ARMNT xdata detects a physically short handler read", async context => {
  const file = createArmntXdata(2 | (1 << 20) | (1 << 28), 20);
  const original = file.read.bind(file);
  context.mock.method(file, "read", (offset: number, size: number) =>
    offset === 16 ? Promise.resolve(new DataView(new ArrayBuffer(0))) : original(offset, size));
  const issues: string[] = [];

  assert.equal(await createArmntUnwindInfoReader(file, rva => rva)(8, issues), null);
  assert.deepEqual(issues, ["ARMNT .xdata handler RVA is truncated."]);
});

void test("ARMNT maximum extended counts remain bounded and use sparse word reads", async context => {
  const file = createArmntXdata(0x3ffff | (1 << 20), 263180, 0xffff | (255 << 16), 101);
  const calls = context.mock.method(file, "read");
  const issues: string[] = [];
  const info = await createArmntUnwindInfoReader(file, rva => rva)(8, issues);

  assert.equal(info?.functionLengthBytes, 524286);
  assert.equal(info?.handlerRva, 101);
  assert.deepEqual(calls.mock.calls.map(call => call.arguments[1]), [4, 4, 1020, 262140, 4]);
  assert.deepEqual(issues, []);
});

for (const word of [armntPackedWord() | (1 << 20) | (1 << 21),
  (armntPackedWord() & ~((1 << 19) | (1 << 16))) | (1 << 20) | (1 << 21),
  (armntPackedWord() & ~(3 << 13)) | (1 << 20)]) {
  void test(`ARMNT accepts supported LR/frame-chain combinations ${word}`, async () => {
    const issues: string[] = [];

    assert.ok(await createArmntUnwindInfoReader(new MockFile(new Uint8Array(0)), () => null)(word, issues));
    assert.deepEqual(issues, []);
  });
}
