import assert from "node:assert/strict";
import { test } from "node:test";
import { createArm64UnwindInfoReader } from "../../../../../analyzers/pe/exception/arm64-unwind-info.js";
import { MockFile } from "../../../../helpers/mock-file.js";

void test("ARM64 unwind reader caches packed metadata", async () => {
  const read = createArm64UnwindInfoReader(new MockFile(new Uint8Array(0)), () => null);
  const issues: string[] = [];
  const packed = await read(5, issues);

  assert.deepEqual(packed, { functionLengthBytes: 4, handlerRva: null,
    hasHandler: false, key: "packed:5", chained: false, version: null });
  assert.equal(await read(5, issues), packed);
  assert.deepEqual(issues, []);
});

void test("ARM64 unwind reader rejects a parent cycle and caches the failure", async context => {
  const bytes = new Uint8Array(16);
  new DataView(bytes.buffer).setUint32(12, 11, true); // Flag 3, parent at RVA 8.
  const file = new MockFile(bytes);
  const calls = context.mock.method(file, "read");
  const read = createArm64UnwindInfoReader(file, rva => rva);
  const issues: string[] = [];

  assert.equal(await read(11, issues), null);
  assert.equal(await read(11, issues), null);
  assert.deepEqual(issues, ["ARM64 chained .pdata entries contain a cycle.",
    "ARM64 chained .pdata entries contain a cycle."]);
  assert.equal(calls.mock.callCount(), 1);
});

const xdataFile = (header: number, size: number, extension = 0): MockFile => {
  const bytes = new Uint8Array(size);
  const view = new DataView(bytes.buffer);
  // Microsoft ARM64 .xdata header: X=bit20, E=bit21, version=bits18..19.
  // https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling#xdata-records
  if (size >= 12) view.setUint32(8, header, true);
  if (size >= 16) view.setUint32(12, extension, true);
  return new MockFile(bytes);
};

for (const [word, size, expected] of [[0, 16, /RVA 0/], [8, 10, /header is truncated/],
  [8, 12, /extended header is truncated/], [8, 16, /record is truncated/]] as const) {
  void test(`ARM64 unwind reader diagnoses invalid xdata ${word}, size ${size}`, async () => {
    const file = xdataFile(size === 16 ? 2 << 27 : 0, size);
    const issues: string[] = [];
    const read = createArm64UnwindInfoReader(file, rva => rva);

    assert.equal(await read(word, issues), null);
    assert.match(issues.join(" | "), expected);
  });
}

void test("ARM64 unwind reader rejects unmapped xdata", async () => {
  const issues: string[] = [];
  const read = createArm64UnwindInfoReader(new MockFile(new Uint8Array(16)), () => null);

  assert.equal(await read(8, issues), null);
  assert.match(issues[0]!, /does not map/);
});

void test("ARM64 unwind reader decodes an extended header with a handler", async () => {
  const file = xdataFile(1 | (1 << 20) | (2 << 18), 24, 1 << 16);
  new DataView(file.data.buffer).setUint32(20, 100, true);
  const reader = new MockFile(file.data);
  const issues: string[] = [];
  const info = await createArm64UnwindInfoReader(reader, rva => rva)(8, issues);

  assert.equal(info?.functionLengthBytes, 4);
  assert.equal(info?.version, 2);
  assert.equal(info?.handlerRva, 100);
  assert.equal(info?.hasHandler, true);
  assert.deepEqual(issues, []);
});

void test("ARM64 unwind reader diagnoses reserved extension bits while decoding the bounded pool", async () => {
  const file = xdataFile(1, 20, (1 << 24) | (1 << 16));
  file.data[16] = 0xe4; // END in the single declared code word.
  const issues: string[] = [];
  const info = await createArm64UnwindInfoReader(new MockFile(file.data), rva => rva)(8, issues);

  assert.equal(info?.unwind?.operations[0]?.opcode, "end");
  assert.deepEqual(issues, ["ARM64 .xdata extended header sets reserved bits."]);
});

void test("ARM64 unwind reader diagnoses a physically short handler read", async context => {
  const file = xdataFile(1 | (1 << 20) | (1 << 21) | (1 << 27), 20);
  const original = file.read.bind(file);
  context.mock.method(file, "read", (offset: number, size: number) =>
    offset === 16 ? Promise.resolve(new DataView(new ArrayBuffer(0))) : original(offset, size));
  const issues: string[] = [];

  assert.equal(await createArm64UnwindInfoReader(file, rva => rva)(8, issues), null);
  assert.match(issues[0]!, /handler RVA is truncated/);
});

void test("ARM64 parent reads stay inside the copied table, even with image bytes after it", async () => {
  const image = new MockFile(new Uint8Array(128));
  const source = new MockFile(new Uint8Array(4));
  const issues: string[] = [];

  assert.equal(await createArm64UnwindInfoReader(image, rva => rva, source, 64)(67, issues), null);
  assert.match(issues[0]!, /target is truncated/);
});

for (const target of [4, 80]) {
  void test(`ARM64 parent outside the copied table resolves image RVA ${target}`, async () => {
    const bytes = new Uint8Array(128);
    new DataView(bytes.buffer).setUint32(target + 4, 5, true);
    const issues: string[] = [];
    const info = await createArm64UnwindInfoReader(new MockFile(bytes), rva => rva,
      new MockFile(new Uint8Array(8)), 64)(target | 3, issues);

    assert.equal(info?.chained, true);
    assert.equal(info?.functionLengthBytes, 4);
    assert.deepEqual(issues, []);
  });
}

void test("ARM64 missing copied parent does not fall back to a valid original image row", async () => {
  const bytes = new Uint8Array(128);
  new DataView(bytes.buffer).setUint32(76, 5, true);
  const source = new MockFile(new Uint8Array(8));
  const issues: string[] = [];

  assert.equal(await createArm64UnwindInfoReader(new MockFile(bytes), rva => rva,
    source, 64, 16)(75, issues), null);
  assert.match(issues[0]!, /target is truncated/);
});

for (const offset of [null, -1, 16]) {
  void test(`ARM64 xdata rejects file offset ${offset} before reading a header`, async () => {
    const issues: string[] = [];
    const read = createArm64UnwindInfoReader(new MockFile(new Uint8Array(16)), () => offset);

    assert.equal(await read(8, issues), null);
    assert.deepEqual(issues, ["ARM64 .pdata entry points to an .xdata RVA that does not map to file data."]);
  });
}

for (const [extra, size, handlerOffset] of [[2 << 22, 28, 24], [(2 << 22) | (1 << 21), 20, 16]] as const) {
  void test(`ARM64 xdata locates handlers with scope bits ${extra}`, async () => {
    const file = xdataFile(1 | (1 << 20) | (1 << 27) | extra, size);
    new DataView(file.data.buffer).setUint32(handlerOffset, 100, true);
    file.data.set([0xe4, 0xe3, 0xe4, 0xe3], handlerOffset - 4); // END at both referenced entry indices.
    const issues: string[] = [];
    const info = await createArm64UnwindInfoReader(new MockFile(file.data), rva => rva)(8, issues);

    assert.equal(info?.handlerRva, 100);
    assert.equal(info?.hasHandler, true);
    assert.deepEqual(issues, []);
  });
}

void test("ARM64 xdata accepts file offset zero and preserves the absence of a handler", async () => {
  const bytes = new Uint8Array(16);
  new DataView(bytes.buffer).setUint32(0, 1 | (1 << 27), true);
  bytes[4] = 0xe4; // END, with the rest of the word unused.
  const issues: string[] = [];
  const info = await createArm64UnwindInfoReader(new MockFile(bytes), rva => rva - 8)(8, issues);

  assert.deepEqual(info, { functionLengthBytes: 4, handlerRva: null, hasHandler: false,
    key: "xdata:8", chained: false, version: 0,
    unwind: { operations: [{ opcode: "end", offset: 0, byteLength: 1, kind: "marker" }], hasDecodeGaps: false } });
  assert.deepEqual(issues, []);
});

void test("ARM64 parent at the copied-table end resolves the original image", async () => {
  const bytes = new Uint8Array(128);
  new DataView(bytes.buffer).setUint32(76, 5, true);
  const issues: string[] = [];
  const info = await createArm64UnwindInfoReader(new MockFile(bytes), rva => rva,
    new MockFile(new Uint8Array(8)), 64)(75, issues);

  assert.equal(info?.key, "chained:72");
  assert.equal(info?.functionLengthBytes, 4);
  assert.deepEqual(issues, []);
});

void test("ARM64 parent selects the copied row and bounds a partial final parent read", async context => {
  const bytes = new Uint8Array(128);
  new DataView(bytes.buffer).setUint32(68, 9, true);
  const sourceBytes = new Uint8Array(12);
  new DataView(sourceBytes.buffer).setUint32(4, 5, true);
  const source = new MockFile(sourceBytes);
  const calls = context.mock.method(source, "read");
  const read = createArm64UnwindInfoReader(new MockFile(bytes), rva => rva, source, 64);
  const issues: string[] = [];

  assert.equal((await read(67, issues))?.functionLengthBytes, 4);
  assert.equal(await read(75, issues), null);
  assert.deepEqual(calls.mock.calls.map(call => call.arguments), [[0, 8], [8, 4]]);
  assert.deepEqual(issues, ["ARM64 chained .pdata target is truncated."]);
});
