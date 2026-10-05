import assert from "node:assert/strict";
import test from "node:test";
import { readNativeAotSectionBytes } from "../../../../analyzers/native-aot/section-bytes.js";
import { createNativeAotInvokeFixture } from "../../../helpers/native-aot-invoke-fixture.js";

void test("reads only the requested NativeAOT section bytes", async () => {
  const fixture = createNativeAotInvokeFixture();
  const issues = new Set<string>();

  const bytes = await readNativeAotSectionBytes(fixture.image, fixture.sections[0]!, issues);

  assert.deepEqual(bytes, fixture.bytes.subarray(fixture.mapRva, fixture.mapRva + fixture.sections[0]!.size!));
  assert.equal(issues.size, 0);
});

void test("preserves the available prefix when a declared section is truncated", async () => {
  const fixture = createNativeAotInvokeFixture();
  const issues = new Set<string>();
  const section = { type: 306, rva: fixture.bytes.length - 3, size: 20 };

  assert.equal((await readNativeAotSectionBytes(fixture.image, section, issues)).length, 3);
  assert.match([...issues].join(" "), /truncated or not fully file-backed/);
});

void test("rejects unknown, negative and fractional sizes", async () => {
  const fixture = createNativeAotInvokeFixture();
  const issues = new Set<string>();

  assert.equal((await readNativeAotSectionBytes(fixture.image, { type: 306, rva: 0, size: null }, issues)).length, 0);
  assert.equal((await readNativeAotSectionBytes(fixture.image, { type: 306, rva: 0, size: -1 }, issues)).length, 0);
  assert.equal((await readNativeAotSectionBytes(fixture.image, { type: 306, rva: 0, size: 0.5 }, issues)).length, 0);
  assert.match([...issues].join(" "), /invalid size/);
});

void test("handles empty and entirely unmapped sections without I/O", async context => {
  const fixture = createNativeAotInvokeFixture();
  const reads = context.mock.method(fixture.image, "readData");
  const issues = new Set<string>();

  assert.equal((await readNativeAotSectionBytes(fixture.image, { type: 306, rva: 0, size: 0 }, issues)).length, 0);
  assert.equal(issues.size, 0);
  assert.equal((await readNativeAotSectionBytes(fixture.image,
    { type: 306, rva: fixture.bytes.length, size: 1 }, issues)).length, 0);
  assert.equal(reads.mock.callCount(), 0);
  assert.match([...issues].join(" "), /not fully file-backed/);
});

void test("reports a negative section size even when no bytes would be read", async () => {
  const fixture = createNativeAotInvokeFixture();
  const issues = new Set<string>();

  assert.equal((await readNativeAotSectionBytes(fixture.image,
    { type: 306, rva: 0, size: -1 }, issues)).length, 0);
  assert.deepEqual([...issues], ["Section has an unknown or invalid size."]);
});

void test("reports null or short reads and confines oversized reads to the declared section", async () => {
  const fixture = createNativeAotInvokeFixture();
  const issues = new Set<string>();
  const section = { type: 306, rva: 0, size: 4 };
  fixture.image.readData = async () => null;

  assert.equal((await readNativeAotSectionBytes(fixture.image, section, issues)).length, 0);
  fixture.image.readData = async () => new DataView(new ArrayBuffer(3));
  assert.equal((await readNativeAotSectionBytes(fixture.image, section, issues)).length, 3);
  fixture.image.readData = async () => new DataView(new ArrayBuffer(5));
  assert.equal((await readNativeAotSectionBytes(fixture.image, section, issues)).length, 4);
  assert.match([...issues].join(" "), /could not be read/);
  assert.match([...issues].join(" "), /truncated prefix/);
});

void test("converts typed and untyped section read failures to warnings", async () => {
  const fixture = createNativeAotInvokeFixture();
  const issues = new Set<string>();
  fixture.image.readData = async () => { throw new Error("I/O error"); };

  assert.equal((await readNativeAotSectionBytes(fixture.image, fixture.sections[0]!, issues)).length, 0);
  fixture.image.readData = async () => { throw "untyped error"; };
  assert.equal((await readNativeAotSectionBytes(fixture.image, fixture.sections[0]!, issues)).length, 0);
  assert.match([...issues].join(" "), /I\/O error/);
  assert.match([...issues].join(" "), /Section read failed/);
});
