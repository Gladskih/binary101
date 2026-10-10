import assert from "node:assert/strict";
import test from "node:test";
import { NativeAotGcDescriptors } from "../../../../analyzers/native-aot/gc-descriptors.js";
import { createNativeAotObjectGcFixture, createNativeAotReferenceArrayGcFixture,
  createNativeAotRepeatingArrayGcFixture } from "../../../helpers/native-aot-gc-fixture.js";

for (const width of [4, 8] as const) {
  void test(`GC object series decode adjusted lengths and offsets at ${width}-byte width`, async () => {
    const fixture = createNativeAotObjectGcFixture(width);

    assert.deepEqual(await new NativeAotGcDescriptors(fixture.references).read(fixture.type), {
      kind: "object", series: [{ offset: width, bytes: width }, { offset: width * 3, bytes: width * 2 }]
    });
    assert.equal(fixture.issues.size, 0);
  });

  void test(`GC reference arrays retain their data offset at ${width}-byte width`, async () => {
    const fixture = createNativeAotReferenceArrayGcFixture(width);

    assert.deepEqual(await new NativeAotGcDescriptors(fixture.references).read(fixture.type),
      { kind: "array-all-references", dataOffset: width * 2 });
    assert.equal(fixture.issues.size, 0);
  });

  void test(`GC value-type arrays decode packed repeating series at ${width}-byte width`, async () => {
    const fixture = createNativeAotRepeatingArrayGcFixture(width);

    assert.deepEqual(await new NativeAotGcDescriptors(fixture.references).read(fixture.type), {
      kind: "array-repeating", firstReferenceOffset: width * 3,
      series: [{ pointerCount: 1, skipBytes: width }, { pointerCount: 2, skipBytes: width }]
    });
    assert.equal(fixture.issues.size, 0);
  });
}

void test("types without GC references do not inspect preceding data", async context => {
  const fixture = createNativeAotObjectGcFixture();
  const reads = context.mock.method(fixture.image, "readData");

  assert.equal(await new NativeAotGcDescriptors(fixture.references).read({ ...fixture.type, flags: 0 }), null);
  assert.equal(await new NativeAotGcDescriptors(fixture.references).read({ ...fixture.type, numVtableSlots: 0 }), null);
  assert.equal(reads.mock.callCount(), 0);
});

void test("malformed counts and storage ranges warn instead of throwing", async () => {
  const fixture = createNativeAotObjectGcFixture();
  const reader = new NativeAotGcDescriptors(fixture.references);
  fixture.word(fixture.type.rva - 8, 0n);

  assert.equal(await reader.read(fixture.type), null);
  fixture.word(fixture.type.rva - 8, 9007199254740993n);
  assert.equal(await reader.read(fixture.type), null);
  fixture.word(fixture.type.rva - 8, 1000n);
  assert.equal(await reader.read(fixture.type), null);
  assert.match([...fixture.issues].join(" "), /GC descriptor/);
});

void test("invalid object lengths, overlapping ranges and array counts never become accepted layouts", async () => {
  const fixture = createNativeAotObjectGcFixture();
  const reader = new NativeAotGcDescriptors(fixture.references);
  fixture.word(fixture.type.rva - 24, -49n);

  assert.equal(await reader.read(fixture.type), null);
  fixture.word(fixture.type.rva - 24, -40n);
  fixture.word(fixture.type.rva - 32, 8n);
  assert.equal(await reader.read(fixture.type), null);
  fixture.word(fixture.type.rva - 8, -2n);
  assert.equal(await reader.read(fixture.type), null);
});

void test("array descriptors validate the component stride and reference-only special encoding", async () => {
  const repeated = createNativeAotRepeatingArrayGcFixture();
  const reference = createNativeAotReferenceArrayGcFixture();
  repeated.type.flags = (0xe1000000 | 32) >>> 0;
  reference.word(reference.type.rva - 24, -16n);

  assert.equal(await new NativeAotGcDescriptors(repeated.references).read(repeated.type), null);
  assert.equal(await new NativeAotGcDescriptors(reference.references).read(reference.type), null);
  assert.match([...repeated.issues].join(" "), /stride/);
  assert.match([...reference.issues].join(" "), /GC descriptor/);
});

for (const [field, value, message] of [
  [16, 9007199254740993n, /safe integer/], [16, 0n, /instance layout/],
  [16, 9n, /instance layout/], [24, -48n, /instance layout/],
  [24, -39n, /instance layout/], [24, 0n, /instance layout/],
  [32, 8n, /instance layout/], [32, 32n, /instance layout/]
] as const) {
  void test(`invalid object GC word at -${field}, value ${value}, warns`, async () => {
    const fixture = createNativeAotObjectGcFixture();
    fixture.word(fixture.type.rva - field, value);

    assert.equal(await new NativeAotGcDescriptors(fixture.references).read(fixture.type), null);
    assert.match([...fixture.issues].join(" "), message);
  });
}

for (const flags of [0x61000008, 0xe1000000, 0xe1000009]) {
  void test(`array GC encoding rejects invalid component flags ${flags.toString(16)}`, async () => {
    const fixture = createNativeAotReferenceArrayGcFixture();

    assert.equal(await new NativeAotGcDescriptors(fixture.references).read({ ...fixture.type, flags }), null);
    assert.match([...fixture.issues].join(" "), /component size/);
  });
}

for (const [field, value, message] of [
  [16, 8n, /first array reference/], [16, 56n, /first array reference/],
  [16, 25n, /first array reference/], [24, 0n, /repeating series/],
  [24, (1n << 32n) | 1n, /repeating series/],
  // Preserve a 40-byte stride but remove the last skip that must reach the leading non-pointer.
  [32, 3n, /stride/]
] as const) {
  void test(`invalid repeated GC word at -${field}, value ${value}, warns`, async () => {
    const fixture = createNativeAotRepeatingArrayGcFixture();
    fixture.word(fixture.type.rva - field, value);

    assert.equal(await new NativeAotGcDescriptors(fixture.references).read(fixture.type), null);
    assert.match([...fixture.issues].join(" "), message);
  });
}

void test("GC reads reject negative, fractional, executable and unmapped locations", async context => {
  const fixture = createNativeAotObjectGcFixture();
  const reader = new NativeAotGcDescriptors(fixture.references);

  assert.equal(await reader.read({ ...fixture.type, rva: 0 }), null);
  assert.equal(await reader.read({ ...fixture.type, rva: 384.5 }), null);
  context.mock.method(fixture.image, "isExecutableAddress", () => true);
  assert.equal(await reader.read(fixture.type), null);
  context.mock.method(fixture.image, "isExecutableAddress", () => false);
  context.mock.method(fixture.image, "isMappedRange", (address: number) => address >= fixture.type.rva - 8);
  assert.equal(await reader.read(fixture.type), null);
  assert.match([...fixture.issues].join(" "), /alignment/);
  assert.match([...fixture.issues].join(" "), /mapped storage/);
});

void test("GC scalar I/O failures and unexpected errors remain warnings", async context => {
  const fixture = createNativeAotObjectGcFixture();
  const reader = new NativeAotGcDescriptors(fixture.references);
  context.mock.method(fixture.references.data, "unsigned", async () => null);

  assert.equal(await reader.read(fixture.type), null);
  assert.match([...fixture.issues].join(" "), /unreadable scalar/);
  context.mock.method(fixture.references.data, "unsigned", async () => { throw null; });
  assert.equal(await reader.read(fixture.type), null);
  assert.match([...fixture.issues].join(" "), /decoding failed/);
});

for (const [field, value] of [[8, 2n], [16, 24n]] as const) {
  void test(`reference-array GC word at -${field} must match the special layout`, async () => {
    const fixture = createNativeAotReferenceArrayGcFixture();
    fixture.word(fixture.type.rva - field, value);

    assert.equal(await new NativeAotGcDescriptors(fixture.references).read(fixture.type), null);
    assert.match([...fixture.issues].join(" "), /reference-array encoding/);
  });
}

void test("the complete object descriptor must fit the mapped range, including its count word", async context => {
  const fixture = createNativeAotObjectGcFixture();
  context.mock.method(fixture.image, "isMappedRange", (_address: number, size: number) => size <= 32);

  assert.equal(await new NativeAotGcDescriptors(fixture.references).read(fixture.type), null);
  assert.match([...fixture.issues].join(" "), /mapped storage/);
});

void test("signed GC words outside exact integer precision are reported before storage validation", async () => {
  const fixture = createNativeAotObjectGcFixture();
  fixture.word(fixture.type.rva - 8, 9007199254740993n);

  assert.equal(await new NativeAotGcDescriptors(fixture.references).read(fixture.type), null);
  assert.match([...fixture.issues].join(" "), /signed scalar exceeds safe integer precision/);
});

void test("a repeating array can start with a reference and end with no skipped bytes", async () => {
  const fixture = createNativeAotRepeatingArrayGcFixture();
  fixture.word(fixture.type.rva - 16, 16n);
  fixture.word(fixture.type.rva - 24, 16n << 32n | 1n);
  fixture.word(fixture.type.rva - 32, 2n);

  assert.deepEqual(await new NativeAotGcDescriptors(fixture.references).read(fixture.type),
    { kind: "array-repeating", firstReferenceOffset: 16,
      series: [{ pointerCount: 1, skipBytes: 16 }, { pointerCount: 2, skipBytes: 0 }] });
  assert.equal(fixture.issues.size, 0);
});

void test("an object descriptor may end exactly at the beginning of the mapped image", async () => {
  const fixture = createNativeAotObjectGcFixture();
  fixture.bytes.copyWithin(0, fixture.type.rva - 40, fixture.type.rva);

  assert.deepEqual(await new NativeAotGcDescriptors(fixture.references).read({ ...fixture.type, rva: 40 }),
    { kind: "object", series: [{ offset: 8, bytes: 8 }, { offset: 24, bytes: 16 }] });
  assert.equal(fixture.issues.size, 0);
});

void test("a mixed array may have just one repeating reference region", async () => {
  const fixture = createNativeAotRepeatingArrayGcFixture();
  fixture.type.flags = 0xe1000010;
  fixture.word(fixture.type.rva - 8, -1n);
  fixture.word(fixture.type.rva - 16, 16n);
  fixture.word(fixture.type.rva - 24, 8n << 32n | 1n);

  assert.deepEqual(await new NativeAotGcDescriptors(fixture.references).read(fixture.type),
    { kind: "array-repeating", firstReferenceOffset: 16, series: [{ pointerCount: 1, skipBytes: 8 }] });
  assert.equal(fixture.issues.size, 0);
});
