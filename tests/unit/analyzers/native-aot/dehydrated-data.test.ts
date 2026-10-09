import assert from "node:assert/strict";
import test from "node:test";
import { NativeAotDehydratedData } from "../../../../analyzers/native-aot/dehydrated-data.js";
import { createFunctionEntryFixture } from "../../../helpers/native-aot-function-map-fixture.js";

const fixtureWithStream = (commands: number[]) => {
  const fixture = createFunctionEntryFixture(new Uint8Array());
  // DehydratedData: destination relptr32, byte commands, followed by relptr32 fixup table.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/DehydratedData.cs
  const streamRva = 0x240;
  const destination = 0x180;
  fixture.view.setInt32(streamRva, destination - streamRva, true);
  fixture.bytes.set(commands, streamRva + 4);
  fixture.sections.push({ type: 207, rva: streamRva, size: 4 + commands.length });
  const fixup = streamRva + 4 + commands.length;
  fixture.view.setInt32(fixup, fixture.codeRvas[1]! - fixup, true);
  return { ...fixture, destination, streamRva };
};

void test("relative relocation reads share hydration and cache success and failure independently of absolute fields", async context => {
  const fixture = fixtureWithStream([2]);
  const data = new NativeAotDehydratedData(fixture.image, fixture.sections, fixture.issues);
  const reads = context.mock.method(fixture.image, "readData");

  assert.equal(await data.relative(fixture.destination), fixture.codeRvas[1]);
  const count = reads.mock.callCount();
  assert.equal(await data.relative(fixture.destination), fixture.codeRvas[1]);
  assert.equal(reads.mock.callCount(), count);
  assert.equal(await data.pointer(fixture.destination), null);
  assert.match([...fixture.issues].join(), /not an absolute pointer/);
  assert.equal(await data.relative(-4), null);
  assert.equal(await data.relative(-4), null);
  assert.match([...fixture.issues].join(), /relative pointer has an invalid mapped range/);
  context.mock.method(fixture.image, "readData", async () => { throw "failure"; });
  assert.equal(await data.relative(0x200), null);
  assert.match([...fixture.issues].join(), /relative pointer read failed/);
});

void test("cached relative storage avoids rereading both valid and failed file-backed fields", async context => {
  const fixture = createFunctionEntryFixture(new Uint8Array());
  fixture.view.setInt32(0x180, fixture.codeRvas[0]! - 0x180, true);
  const data = new NativeAotDehydratedData(fixture.image, fixture.sections, fixture.issues);
  const reads = context.mock.method(fixture.image, "readData");

  assert.equal(await data.relative(0x180), fixture.codeRvas[0]);
  assert.equal(reads.mock.callCount(), 4);
  assert.equal(await data.relative(0x180), fixture.codeRvas[0]);
  assert.equal(reads.mock.callCount(), 4);
  context.mock.method(fixture.image, "readData", async () => null);
  assert.equal(await data.relative(0x184), null);
  const failures = context.mock.method(fixture.image, "readData");
  assert.equal(await data.relative(0x184), null);
  assert.equal(failures.mock.callCount(), 0);
});

void test("dehydration restores sparse absolute pointers and skips zero/data runs", async () => {
  // ZeroFill8, PtrReloc(index0), Copy2 literal bytes.
  const fixture = fixtureWithStream([65, 3, 16, 11, 22]);
  const data = new NativeAotDehydratedData(fixture.image, fixture.sections, fixture.issues);

  assert.equal(await data.pointer(fixture.destination), null);
  assert.equal(await data.pointer(fixture.destination + 8), fixture.codeRvas[1]);
  assert.equal(fixture.issues.size, 0);
});

void test("fixed scalars restore mixed Copy/ZeroFill fields and share the loaded stream", async context => {
  const fixture = fixtureWithStream([8, 7, 25]);
  const reads = context.mock.method(fixture.image, "readData");
  const data = new NativeAotDehydratedData(fixture.image, fixture.sections, fixture.issues);

  assert.equal(await data.unsigned(fixture.destination, 4), 7);
  assert.equal(await data.unsigned(fixture.destination + 2, 2), 0);
  assert.equal(reads.mock.callCount(), 2);
  assert.deepEqual([...fixture.issues], []);
});

void test("scalar failures become visible warnings instead of escaping", async context => {
  const fixture = fixtureWithStream([3]);
  const data = new NativeAotDehydratedData(fixture.image, fixture.sections, fixture.issues);

  assert.equal(await data.unsigned(fixture.destination, 4), null);
  assert.match([...fixture.issues].join(), /overlaps/);
  context.mock.method(fixture.image, "readData", async () => { throw "failure"; });
  assert.equal(await data.unsigned(0x200, 4), null);
  assert.match([...fixture.issues].join(), /scalar read failed/);
});

void test("dehydration restores inline absolute and relative relocations", async () => {
  // InlinePtrReloc(count1), inline target, InlineRelPtr32Reloc(count1), inline target.
  const fixture = fixtureWithStream([13, 0, 0, 0, 0, 12, 0, 0, 0, 0]);
  fixture.view.setInt32(fixture.streamRva + 5, fixture.codeRvas[0]! - fixture.streamRva - 5, true);
  fixture.view.setInt32(fixture.streamRva + 10, fixture.codeRvas[1]! - fixture.streamRva - 10, true);
  const data = new NativeAotDehydratedData(fixture.image, fixture.sections, fixture.issues);

  assert.equal(await data.pointer(fixture.destination), fixture.codeRvas[0]);
  assert.equal(await data.pointer(fixture.destination + 8), null);
  assert.match([...fixture.issues].join(" "), /not an absolute pointer/);
});

void test("dehydration preserves a decoded pointer before a malformed command", async () => {
  const fixture = fixtureWithStream([3, 7]);
  const data = new NativeAotDehydratedData(fixture.image, fixture.sections, fixture.issues);

  assert.equal(await data.pointer(fixture.destination), fixture.codeRvas[1]);
  assert.match([...fixture.issues].join(" "), /unknown/);
});

void test("dehydration copies an unaligned literal pointer and resolves it in image addresses", async context => {
  const fixture = fixtureWithStream([64, 0, 0, 0, 0, 0, 0, 0, 0]);
  fixture.view.setBigUint64(fixture.streamRva + 5, BigInt(fixture.codeRvas[0]!), true);
  fixture.image.toImageAddress = value => Number(value);
  const reads = context.mock.method(fixture.image, "readData");
  const data = new NativeAotDehydratedData(fixture.image, fixture.sections, fixture.issues);

  assert.equal(await data.pointer(fixture.destination), fixture.codeRvas[0]);
  assert.equal(await data.pointer(fixture.destination), fixture.codeRvas[0]);
  assert.equal(reads.mock.callCount(), 2);
  assert.equal(fixture.issues.size, 0);
});

void test("dehydration handles zero literal pointers and reports incomplete pointer fields", async () => {
  const zero = fixtureWithStream([64, 0, 0, 0, 0, 0, 0, 0, 0]);
  const short = fixtureWithStream([32, 0, 0, 0, 0]);

  assert.equal(await new NativeAotDehydratedData(zero.image, zero.sections, zero.issues).pointer(zero.destination),
    null);
  assert.equal(zero.issues.size, 0);
  assert.equal(await new NativeAotDehydratedData(short.image, short.sections, short.issues)
    .pointer(short.destination), null);
  assert.match([...short.issues].join(" "), /boundary/);
});

void test("dehydration rejects ambiguous streams and unresolved stored pointers", async () => {
  const fixture = fixtureWithStream([65]);
  fixture.sections.push({ ...fixture.sections.at(-1)! });
  const data = new NativeAotDehydratedData(fixture.image, fixture.sections, fixture.issues);

  assert.equal(await data.pointer(fixture.destination), null);
  assert.match([...fixture.issues].join(" "), /ambiguous/);
  assert.match([...fixture.issues].join(" "), /unresolved/);
});

void test("addresses at or beyond a hydrated run end use file-backed storage", async () => {
  const fixture = fixtureWithStream([3]);
  fixture.image.readPointerValue = async () => 1n;
  fixture.image.readPointerTarget = async () => fixture.codeRvas[0]!;
  const data = new NativeAotDehydratedData(fixture.image, fixture.sections, fixture.issues);

  assert.equal(await data.pointer(fixture.destination + 8), fixture.codeRvas[0]);
  assert.equal(await data.pointer(fixture.destination + 16), fixture.codeRvas[0]);
  assert.equal(fixture.issues.size, 0);
});

void test("stored pointers require a file-backed aligned field and preserve zero as initialized", async () => {
  const fixture = createFunctionEntryFixture(new Uint8Array());
  fixture.image.readPointerValue = async () => 0n;
  fixture.image.readPointerTarget = async () => fixture.codeRvas[0]!;
  const data = new NativeAotDehydratedData(fixture.image, fixture.sections, fixture.issues);

  assert.equal(await data.pointer(0x180), null);
  assert.equal(fixture.issues.size, 0);
  assert.equal(await data.pointer(-8), null);
  assert.deepEqual([...fixture.issues],
    ["NativeAOT absolute pointer is not readable in the image or DehydratedData."]);
});

void test("partially addressed pointer runs are rejected even if enough destination bytes remain", async context => {
  const fixture = fixtureWithStream([3]);
  const data = new NativeAotDehydratedData(fixture.image, fixture.sections, fixture.issues);
  context.mock.method(fixture.image, "readData");
  fixture.image.pointerSize = 4;

  assert.equal(await data.pointer(fixture.destination + 1), null);
  assert.match([...fixture.issues].join(" "), /boundary/);
});

void test("copied pointers retain 32-bit values and report short or unresolved reads", async context => {
  const fixture = fixtureWithStream([32, 64, 0, 0, 0]);
  fixture.image.pointerSize = 4;
  fixture.image.toImageAddress = value => Number(value);
  const data = new NativeAotDehydratedData(fixture.image, fixture.sections, fixture.issues);

  assert.equal(await data.pointer(fixture.destination), fixture.codeRvas[0]);
  const read = fixture.image.readData;
  context.mock.method(fixture.image, "readData", async (address: number, size: number, alignment: number) =>
    address === fixture.streamRva + 5 ? new DataView(new ArrayBuffer(3)) : read(address, size, alignment));
  assert.equal(await new NativeAotDehydratedData(fixture.image, fixture.sections, fixture.issues)
    .pointer(fixture.destination), null);
  assert.match([...fixture.issues].join(" "), /copied pointer is truncated/);
});

void test("unresolved copied pointers produce a visible warning instead of a raw VA", async () => {
  const fixture = fixtureWithStream([64, 64, 0, 0, 0, 0, 0, 0, 0]);

  assert.equal(await new NativeAotDehydratedData(fixture.image, fixture.sections, fixture.issues)
    .pointer(fixture.destination), null);
  assert.deepEqual([...fixture.issues], ["NativeAOT copied pointer could not be resolved."]);
});

void test("untyped stored pointer failures produce warnings", async () => {
  const fixture = createFunctionEntryFixture(new Uint8Array());
  fixture.image.readPointerValue = async () => { throw "untyped I/O error"; };

  assert.equal(await new NativeAotDehydratedData(fixture.image, fixture.sections, fixture.issues).pointer(0x180), null);
  assert.deepEqual([...fixture.issues], ["NativeAOT absolute pointer read failed."]);
});
