import assert from "node:assert/strict";
import { test } from "node:test";
import { findTd32Location } from "../../../../../analyzers/pe/debug/td32-location.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { createTd32 } from "../../../../fixtures/pe-td32.js";
import { legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

for (const signature of ["FB09", "FB0A"]) {
  void test(`TD32 ${signature} trailer locates the container after an arbitrary prefix`, async () => {
    const bytes = createTd32([], signature);
    const file = new MockFile(Uint8Array.from([0, ...bytes]));
    const warnings: string[] = [];
    const location = await findTd32Location(file, 0, file.size, message => warnings.push(message));

    assert.deepEqual(location, { offset: 1, size: bytes.length });
    assert.deepEqual(warnings, []);
  });
}

for (const size of [0, 1, 7]) {
  void test(`TD32 location ignores a ${size}-byte candidate without reading beyond it`, async () => {
    const warnings: string[] = [];

    assert.equal(await findTd32Location(new MockFile(new Uint8Array(size)), 0, size,
      message => warnings.push(message)), null);
    assert.deepEqual(warnings, []);
  });
}

for (const displacement of [0, 8, 17, 0xffffffff]) {
  void test(`TD32 location rejects invalid trailer displacement ${displacement}`, async context => {
    const file = new MockFile(Uint8Array.from([0, 0, 0, 0,
      ...new TextEncoder().encode("FB09"), ...legacyU32(displacement)]));
    const warnings: string[] = [];
    const read = file.read.bind(file);
    const ranges: [number, number][] = [];
    context.mock.method(file, "read", async (offset: number, size: number) => {
      ranges.push([offset, size]);
      return read(offset, size);
    });

    assert.equal(await findTd32Location(file, 0, file.size, message => warnings.push(message)), null);
    assert.match(warnings.join(" | "), /trailer/);
    assert.ok(ranges.every(([offset, size]) => offset >= 0 && offset + size <= file.size));
  });
}

void test("TD32 trailer permits a minimal eight-byte header plus eight-byte footer", async () => {
  const file = new MockFile(Uint8Array.from([...new TextEncoder().encode("FB09"), ...legacyU32(0),
    ...new TextEncoder().encode("FB09"), ...legacyU32(16)]));
  const warnings: string[] = [];

  assert.deepEqual(await findTd32Location(file, 0, file.size, message => warnings.push(message)),
    { offset: 0, size: 16 });
  assert.deepEqual(warnings, []);
});

void test("TD32 location rejects a mismatched trailer and preserves a recognized leading header", async () => {
  const bytes = createTd32([]);
  bytes.set(new TextEncoder().encode("FB0A"), bytes.length - 8);
  const warnings: string[] = [];
  const file = new MockFile(bytes);

  assert.deepEqual(await findTd32Location(file, 0, file.size, message => warnings.push(message)),
    { offset: 0, size: file.size });
  assert.match(warnings.join(" | "), /trailer/);
});

void test("TD32 location does not scan for unanchored magic inside unrelated bytes", async () => {
  const file = new MockFile(Uint8Array.from([0, ...createTd32([]).slice(0, -8), ...new Uint8Array(8)]));
  const warnings: string[] = [];

  assert.equal(await findTd32Location(file, 0, file.size, message => warnings.push(message)), null);
  assert.deepEqual(warnings, []);
});

void test("TD32 location preserves a leading header when its trailer is absent", async () => {
  const file = new MockFile(createTd32([]).slice(0, -8));
  const warnings: string[] = [];

  assert.deepEqual(await findTd32Location(file, 0, file.size, message => warnings.push(message)),
    { offset: 0, size: file.size });
  assert.deepEqual(warnings, []);
});

void test("TD32 location read failures become visible warnings", async context => {
  const file = new MockFile(createTd32([]));
  context.mock.method(file, "read", async () => { throw new Error("read failed"); });
  const warnings: string[] = [];

  assert.equal(await findTd32Location(file, 0, file.size, message => warnings.push(message)), null);
  assert.match(warnings.join(" | "), /read failed/);
});

for (const shortReadAt of [0, 1]) {
  void test(`TD32 location handles a short physical read at anchor ${shortReadAt}`, async context => {
    const file = new MockFile(Uint8Array.from([0, ...createTd32([])]));
    const read = file.read.bind(file);
    let calls = 0;
    context.mock.method(file, "read", async (offset: number, size: number) =>
      calls++ === shortReadAt ? new DataView(new ArrayBuffer(0)) : read(offset, size));
    const warnings: string[] = [];

    assert.equal(await findTd32Location(file, 0, file.size, message => warnings.push(message)), null);
    assert.match(warnings.join(" | "), /trailer/);
  });
}

void test("TD32 location handles a short leading-header read after an unrecognized footer", async context => {
  const file = new MockFile(new Uint8Array(8));
  const read = file.read.bind(file);
  context.mock.method(file, "read", async (offset: number, size: number) =>
    size === 4 ? new DataView(new ArrayBuffer(0)) : read(offset, size));
  const warnings: string[] = [];

  assert.equal(await findTd32Location(file, 0, file.size, message => warnings.push(message)), null);
  assert.deepEqual(warnings, []);
});

for (const [offset, size] of [[-1, 8], [0, -1], [1, 8], [0, NaN], [0.5, 4], [0, Infinity]] as const) {
  void test(`TD32 location rejects an invalid file range ${offset}, ${size}`, async () => {
    const warnings: string[] = [];

    assert.equal(await findTd32Location(new MockFile(new Uint8Array(8)), offset, size,
      message => warnings.push(message)), null);
    assert.match(warnings.join(" | "), /bounds/);
  });
}
