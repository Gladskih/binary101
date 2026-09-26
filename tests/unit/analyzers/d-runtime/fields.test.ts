import assert from "node:assert/strict";
import { test } from "node:test";
import { readDExact, readDModuleName, readDPointerArray } from "../../../../analyzers/d-runtime/fields.js";
import {
  createDModuleFixture, createDPointerArrayFixture, createOutOfBoundsDArrayFixture,
  createInvalidDArrayFixture, createLongDNameFixture, createMultiWindowDArrayFixture,
  D_TEST_ABI, D_TEST_IO, D_TEST_MEMORY
} from "../../../fixtures/d-runtime.js";

for (const name of ["dbghelp.5460", "пример.模块"]) {
  void test(`reads compiler-generated or Unicode name ${name}`, async () => {
    const fixture = createDModuleFixture();
    fixture.write.name(name);

    assert.equal(await readDModuleName(fixture.image, fixture.fieldAddress("name")), name);
  });
}

void test("handles empty pointer arrays", async () => {
  const fixture = createDPointerArrayFixture([]);

  assert.deepEqual(await readDPointerArray(fixture.image, fixture.address), []);
});

void test("rejects truncated array contents", async () => {
  const fixture = createDPointerArrayFixture([]);
  fixture.writeCount(1n);
  fixture.image.isMapped = () => true;

  assert.equal(await readDPointerArray(fixture.image, fixture.address), null);
});

void test("rejects missing and truncated array counts", async () => {
  const fixture = createDPointerArrayFixture([]);

  assert.equal(await readDPointerArray(fixture.image, fixture.address + 1n), null);
  assert.equal(await readDPointerArray(fixture.image, D_TEST_MEMORY.unmappedAddress), null);
  assert.equal(await readDExact(fixture.image, D_TEST_MEMORY.unmappedAddress,
    D_TEST_ABI.headerBytes), null);
});

void test("rejects missing names", async () => {
  assert.equal(await readDModuleName(createDModuleFixture().image, D_TEST_MEMORY.unmappedAddress), null);
});

void test("stops at an empty name read instead of looping", async () => {
  const fixture = createDModuleFixture();
  fixture.image.read = async () => new DataView(new ArrayBuffer(0));

  assert.equal(await readDModuleName(fixture.image, fixture.fieldAddress("name")), null);
});

for (const name of ["", "<invalid>", "sample<invalid>", "sample..module", "."]) {
  void test(`rejects empty or implausible module name ${JSON.stringify(name)}`, async () => {
    const fixture = createDModuleFixture();
    fixture.write.name(name);

    assert.equal(await readDModuleName(fixture.image, fixture.fieldAddress("name")), null);
  });
}

void test("decodes multi-element pointer arrays in order", async () => {
  const fixture = createDPointerArrayFixture([D_TEST_MEMORY.moduleAddress, D_TEST_MEMORY.classAddress]);

  assert.deepEqual(await readDPointerArray(fixture.image, fixture.address),
    [D_TEST_MEMORY.moduleAddress, D_TEST_MEMORY.classAddress]);
});

void test("reads pointer arrays across windows without truncation", async () => {
  const fixture = createMultiWindowDArrayFixture();

  assert.equal((await readDPointerArray(fixture.image, fixture.address))?.length,
    fixture.values.length);
});

void test("reads an array payload exactly one window long without an extra EOF read", async () => {
  const fixture = createMultiWindowDArrayFixture(D_TEST_IO.readWindowBytes / D_TEST_ABI.pointer64Bytes);

  assert.deepEqual(await readDPointerArray(fixture.image, fixture.address), fixture.values);
});

void test("rejects the first invalid reference without reading the rest of a large array", async () => {
  const fixture = createInvalidDArrayFixture();

  assert.equal(await readDPointerArray(fixture.image, fixture.address,
    address => fixture.image.isMapped(address, D_TEST_ABI.headerBytes)), null);
});

void test("rejects file-backed size overruns before reading payloads", async () => {
  const fixture = createOutOfBoundsDArrayFixture();

  assert.equal(await readDPointerArray(fixture.image, fixture.address), null);
});

void test("reads long names and preserves UTF-8 split across windows", async () => {
  const fixture = createLongDNameFixture();

  assert.equal(await readDModuleName(fixture.image, fixture.fieldAddress("name")), fixture.record.name);
});

void test("accepts a name whose terminating NUL starts the next read window", async () => {
  const fixture = createLongDNameFixture("A".repeat(D_TEST_IO.readWindowBytes));

  assert.equal(await readDModuleName(fixture.image, fixture.fieldAddress("name")), fixture.record.name);
});

for (const prefix of ["A", "A".repeat(D_TEST_IO.readWindowBytes - 1)]) {
  void test(`rejects incomplete UTF-8 after a ${prefix.length}-byte name prefix`, async () => {
    const fixture = createLongDNameFixture();
    fixture.write.truncatedUtf8Name(prefix);

    assert.equal(await readDModuleName(fixture.image, fixture.fieldAddress("name")), null);
  });
}

void test("handles I/O rejection while reading a name", async () => {
  const fixture = createDModuleFixture();
  fixture.image.read = async () => { throw new Error("File became unreadable"); };

  assert.equal(await readDModuleName(fixture.image, fixture.fieldAddress("name")), null);
});

void test("rejects counts whose byte size cannot be represented safely", async () => {
  const fixture = createDPointerArrayFixture([]);
  // A size_t with its high bit set cannot fit a JavaScript safe byte offset.
  fixture.writeCount(1n << BigInt(D_TEST_ABI.pointer64Bytes * 8 - 1));

  assert.equal(await readDPointerArray(fixture.image, fixture.address), null);
});
