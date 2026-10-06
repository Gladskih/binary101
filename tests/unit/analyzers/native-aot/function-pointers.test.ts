import assert from "node:assert/strict";
import test from "node:test";
import { NativeAotFunctionPointers } from "../../../../analyzers/native-aot/function-pointers.js";
import { NativeAotDehydratedData } from "../../../../analyzers/native-aot/dehydrated-data.js";
import { createFunctionEntryFixture } from "../../../helpers/native-aot-function-map-fixture.js";

void test("tagged function descriptors yield canonical code and never the instantiation argument", async () => {
  const fixture = createFunctionEntryFixture(new Uint8Array());
  const descriptor = 0x180;
  fixture.image.readPointerValue = async () => 1n;
  fixture.image.readPointerTarget = async (address: number) =>
    address === descriptor ? fixture.codeRvas[1]! : fixture.fixupsRva;
  const pointers = new NativeAotFunctionPointers(new NativeAotDehydratedData(fixture.image,
    fixture.sections, fixture.issues), fixture.issues);

  assert.equal(await pointers.resolve(descriptor + 2), fixture.codeRvas[1]);
  assert.equal(fixture.issues.size, 0);
});

void test("function pointers reject invalid addresses and malformed descriptors", async () => {
  const fixture = createFunctionEntryFixture(new Uint8Array());
  const pointers = new NativeAotFunctionPointers(new NativeAotDehydratedData(fixture.image,
    fixture.sections, fixture.issues), fixture.issues);

  assert.equal(await pointers.resolve(-1), null);
  assert.equal(await pointers.resolve(0.5), null);
  assert.equal(await pointers.resolve(0x183), null);
  assert.equal(await pointers.resolve(0x182), null);
  assert.equal(await pointers.resolve(fixture.fixupsRva), null);
  assert.match([...fixture.issues].join(" "), /descriptor/);
});

void test("function pointer cache avoids repeated descriptor and target validation", async context => {
  const fixture = createFunctionEntryFixture(new Uint8Array());
  const executable = context.mock.method(fixture.image, "isExecutableAddress");
  const pointers = new NativeAotFunctionPointers(new NativeAotDehydratedData(fixture.image,
    fixture.sections, fixture.issues), fixture.issues);

  assert.equal(await pointers.resolve(fixture.codeRvas[0]!), fixture.codeRvas[0]);
  assert.equal(await pointers.resolve(fixture.codeRvas[0]!), fixture.codeRvas[0]);
  assert.equal(executable.mock.callCount(), 1);
});

void test("invalid pointer values are rejected before invoking the image adapter", async context => {
  const fixture = createFunctionEntryFixture(new Uint8Array());
  const executable = context.mock.method(fixture.image, "isExecutableAddress", () => true);
  const pointers = new NativeAotFunctionPointers(new NativeAotDehydratedData(fixture.image,
    fixture.sections, fixture.issues), fixture.issues);

  assert.equal(await pointers.resolve(-1), null);
  assert.equal(await pointers.resolve(0.5), null);
  assert.equal(executable.mock.callCount(), 0);
  assert.deepEqual([...fixture.issues], ["Invalid NativeAOT function pointer."]);
  assert.equal(await pointers.resolve(0), 0);
});

void test("tagged descriptors check their complete range and alignment", async context => {
  const fixture = createFunctionEntryFixture(new Uint8Array());
  const mapped = context.mock.method(fixture.image, "isMappedRange",
    (_address: number, size: number) => size === fixture.image.pointerSize);
  const data = new NativeAotDehydratedData(fixture.image, fixture.sections, fixture.issues);
  context.mock.method(data, "pointer", async () => fixture.codeRvas[0]!);
  const pointers = new NativeAotFunctionPointers(data, fixture.issues);

  assert.equal(await pointers.resolve(0x186), null);
  assert.equal(mapped.mock.callCount(), 0);
  assert.equal(await pointers.resolve(0x182), null);
  assert.equal(mapped.mock.calls[0]?.arguments[1], 16);
  assert.deepEqual([...fixture.issues], ["NativeAOT generic method descriptor is unaligned or out of bounds."]);
});

void test("descriptor context pointers remain data and must be mapped", async context => {
  const fixture = createFunctionEntryFixture(new Uint8Array());
  const data = new NativeAotDehydratedData(fixture.image, fixture.sections, fixture.issues);
  const pointer = context.mock.method(data, "pointer",
    async (address: number) => address === 0x180 ? fixture.codeRvas[0]! : 0x800);
  const pointers = new NativeAotFunctionPointers(data, fixture.issues);

  assert.equal(await pointers.resolve(0x182), null);
  assert.deepEqual(pointer.mock.calls.map(call => call.arguments), [[0x180], [0x188]]);
  assert.deepEqual([...fixture.issues],
    ["NativeAOT generic method descriptor has an invalid code or context pointer."]);
});

void test("descriptors reject data as code and null contexts", async context => {
  const fixture = createFunctionEntryFixture(new Uint8Array());
  const data = new NativeAotDehydratedData(fixture.image, fixture.sections, fixture.issues);
  context.mock.method(data, "pointer", async (address: number) => address === 0x180 ? fixture.fixupsRva : null);
  const pointers = new NativeAotFunctionPointers(data, fixture.issues);

  assert.equal(await pointers.resolve(0x182), null);
  assert.deepEqual([...fixture.issues],
    ["NativeAOT generic method descriptor has an invalid code or context pointer."]);
});

// The mapped descriptor at 0x180 is data. A valid context must not mask an invalid method field.
for (const method of [null, 0x180]) {
  void test(`descriptors reject method pointer ${method} independently of the context`, async context => {
    const fixture = createFunctionEntryFixture(new Uint8Array());
    const data = new NativeAotDehydratedData(fixture.image, fixture.sections, fixture.issues);
    context.mock.method(data, "pointer", async (address: number) =>
      address === 0x180 ? method : fixture.fixupsRva);
    const pointers = new NativeAotFunctionPointers(data, fixture.issues);

    assert.equal(await pointers.resolve(0x182), null);
    assert.deepEqual([...fixture.issues],
      ["NativeAOT generic method descriptor has an invalid code or context pointer."]);
  });
}

void test("direct function pointers report non-executable and untyped image failures", async () => {
  const fixture = createFunctionEntryFixture(new Uint8Array());
  const pointers = new NativeAotFunctionPointers(new NativeAotDehydratedData(fixture.image,
    fixture.sections, fixture.issues), fixture.issues);

  assert.equal(await pointers.resolve(fixture.fixupsRva), null);
  assert.deepEqual([...fixture.issues],
    ["NativeAOT function pointer target is not file-backed executable code."]);
  fixture.image.isExecutableAddress = () => { throw "untyped error"; };
  assert.equal(await pointers.resolve(0), null);
  assert.match([...fixture.issues].join(" "), /NativeAOT function pointer read failed/);
});
