import assert from "node:assert/strict";
import { test } from "node:test";
import { parseDModuleInfo } from "../../../../analyzers/d-runtime/module-info.js";
import {
  createAllDCallbacksFixture, createBigEndianDModuleFixture, createDModuleFixture,
  createStandaloneDModuleFixture, D_TEST_ABI, D_TEST_IO, D_TEST_MEMORY,
  truncateDModuleFields, truncateDModuleHeader
} from "../../../fixtures/d-runtime.js";

for (const pointerSize of [D_TEST_ABI.pointer32Bytes, D_TEST_ABI.pointer64Bytes]) {
  void test(`parses D ModuleInfo with ${pointerSize}-byte pointers`, async () => {
    const fixture = createDModuleFixture(pointerSize);

    assert.deepEqual(await parseDModuleInfo(fixture.image, fixture.record.address), fixture.record);
  });
  void test(`respects big-endian address spaces with ${pointerSize}-byte pointers`, async () => {
    const fixture = createBigEndianDModuleFixture(pointerSize);

    assert.deepEqual(await parseDModuleInfo(fixture.image, fixture.record.address), fixture.record);
  });
}

void test("rejects unknown flags instead of guessing a future layout", async () => {
  const fixture = createStandaloneDModuleFixture();
  // First undefined bit above MIname (0x1000), per the pinned object.d flag enum.
  fixture.write.flags(D_TEST_ABI.flags.name | 0x2000);

  assert.equal(await parseDModuleInfo(fixture.image, fixture.record.address), null);
});

void test("rejects non-executable callbacks", async () => {
  const fixture = createDModuleFixture();
  fixture.write.callback(0, fixture.record.address);

  assert.equal(await parseDModuleInfo(fixture.image, fixture.record.address), null);
});

void test("rejects a NULL callback even if an image maps address zero as executable", async () => {
  const fixture = createDModuleFixture();
  fixture.write.callback(0, 0n);
  fixture.image.isExecutable = () => true;

  assert.equal(await parseDModuleInfo(fixture.image, fixture.record.address), null);
});

void test("rejects NULL imported references independently of the image mapping", async () => {
  const fixture = createDModuleFixture();
  fixture.write.importedModule(0, 0n);
  fixture.image.isMapped = () => true;

  assert.equal(await parseDModuleInfo(fixture.image, fixture.record.address), null);
});

void test("rejects oversized counts without allocating or walking them", async () => {
  const fixture = createDModuleFixture();
  fixture.write.importCount(BigInt(D_TEST_IO.readWindowBytes / fixture.image.pointerSize));

  assert.equal(await parseDModuleInfo(fixture.image, fixture.record.address), null);
});

void test("rejects truncated headers", async () => {
  const fixture = createDModuleFixture();
  truncateDModuleHeader(fixture);

  assert.equal(await parseDModuleInfo(fixture.image, fixture.record.address), null);
});

void test("rejects truncated variable fields", async () => {
  const fixture = createDModuleFixture();
  truncateDModuleFields(fixture);

  assert.equal(await parseDModuleInfo(fixture.image, fixture.record.address), null);
});

void test("rejects unterminated names", async () => {
  const fixture = createDModuleFixture();
  fixture.write.unterminatedName();

  assert.equal(await parseDModuleInfo(fixture.image, fixture.record.address), null);
});

void test("rejects invalid UTF-8", async () => {
  const fixture = createDModuleFixture();
  fixture.write.invalidUtf8Name();

  assert.equal(await parseDModuleInfo(fixture.image, fixture.record.address), null);
});

void test("parses standalone modules without variable arrays or callbacks", async () => {
  const fixture = createStandaloneDModuleFixture();

  assert.deepEqual(await parseDModuleInfo(fixture.image, fixture.record.address), fixture.record);
});

void test("rejects records without the name flag", async () => {
  const fixture = createDModuleFixture();
  fixture.write.flags(D_TEST_ABI.flags.standalone);

  assert.equal(await parseDModuleInfo(fixture.image, fixture.record.address), null);
});

void test("rejects misaligned and negative addresses", async () => {
  const fixture = createDModuleFixture();
  fixture.image.read = () => { throw new Error("Must reject invalid addresses before reading"); };

  assert.equal(await parseDModuleInfo(fixture.image, fixture.record.address + 1n), null);
  assert.equal(await parseDModuleInfo(fixture.image, -BigInt(fixture.image.pointerSize)), null);
});

void test("rejects unmapped imported module pointers", async () => {
  const fixture = createDModuleFixture();
  fixture.write.importedModule(0, D_TEST_MEMORY.unmappedAddress);

  assert.equal(await parseDModuleInfo(fixture.image, fixture.record.address), null);
});

void test("rejects misaligned imported module pointers", async () => {
  const fixture = createDModuleFixture();
  fixture.write.importedModule(0, fixture.record.address + 1n);

  assert.equal(await parseDModuleInfo(fixture.image, fixture.record.address), null);
});

void test("rejects unmapped local class pointers", async () => {
  const fixture = createDModuleFixture();
  fixture.write.localClass(0, D_TEST_MEMORY.unmappedAddress);

  assert.equal(await parseDModuleInfo(fixture.image, fixture.record.address), null);
});

void test("rejects truncated local class arrays", async () => {
  const fixture = createDModuleFixture();
  fixture.write.classCount(BigInt(D_TEST_IO.readWindowBytes / fixture.image.pointerSize - 1));

  assert.equal(await parseDModuleInfo(fixture.image, fixture.record.address), null);
});

void test("parses every callback in ABI field order", async () => {
  const fixture = createAllDCallbacksFixture();

  assert.deepEqual(await parseDModuleInfo(fixture.image, fixture.record.address), fixture.record);
});
