import assert from "node:assert/strict";
import test from "node:test";
import { readNativeAotDehydratedRuns } from "../../../../analyzers/native-aot/dehydrated-stream.js";
import { createFunctionEntryFixture } from "../../../helpers/native-aot-function-map-fixture.js";

void test("dehydration decodes the full three-byte payload without allocating hydrated memory", async () => {
  const { image, issues } = createFunctionEntryFixture(new Uint8Array());
  image.isMappedRange = () => true;
  // Extra payload widths 1,2,3; MaxShortPayload=28 from DehydratedData.cs.
  const bytes = Uint8Array.of(0, 0, 0, 0, 233, 1, 241, 0, 1, 249, 0, 0, 1);

  assert.deepEqual(await readNativeAotDehydratedRuns(image, { type: 207, rva: 0x180, size: bytes.length },
    bytes, issues), [{ kind: "zero", rva: 0x180, size: 29 },
    { kind: "zero", rva: 0x180 + 29, size: 284 },
    { kind: "zero", rva: 0x180 + 29 + 284, size: 65564 }]);
  assert.equal(issues.size, 0);
});

void test("dehydration rejects short headers, command operands and unmapped output", async () => {
  const { image, issues } = createFunctionEntryFixture(new Uint8Array());
  const section = { type: 207, rva: 0, size: 5 };

  assert.deepEqual(await readNativeAotDehydratedRuns(image, section, Uint8Array.of(0), issues), []);
  assert.deepEqual(await readNativeAotDehydratedRuns(image, section, Uint8Array.of(0, 0, 0, 0, 249), issues), []);
  assert.deepEqual(await readNativeAotDehydratedRuns(image, section, Uint8Array.of(0, 0, 0, 0, 16), issues), []);
  image.isMappedRange = () => false;
  assert.deepEqual(await readNativeAotDehydratedRuns(image, section, Uint8Array.of(0, 0, 0, 0, 65), issues), []);
  assert.match([...issues].join(" "), /truncated/);
  assert.match([...issues].join(" "), /outside/);
});

void test("exactly four bytes form an empty command stream and shorter headers warn precisely", async () => {
  const { image, issues } = createFunctionEntryFixture(new Uint8Array());
  const section = { type: 207, rva: 0x180, size: 4 };

  assert.deepEqual(await readNativeAotDehydratedRuns(image, section, new Uint8Array(4), issues), []);
  assert.equal(issues.size, 0);
  assert.deepEqual(await readNativeAotDehydratedRuns(image, section, new Uint8Array(3), issues), []);
  assert.deepEqual([...issues], ["DehydratedData destination pointer is truncated."]);
});

void test("dehydration looks up a nonzero fixup index using its signed slot-relative target", async () => {
  const fixture = createFunctionEntryFixture(new Uint8Array());
  const section = { type: 207, rva: 0x180, size: 5 };
  fixture.view.setInt32(0x189, fixture.codeRvas[0]! - 0x189, true);

  assert.deepEqual(await readNativeAotDehydratedRuns(fixture.image, section,
    Uint8Array.of(0, 0, 0, 0, 11), fixture.issues),
  [{ kind: "pointer", rva: 0x180, size: 8, target: fixture.codeRvas[0] }]);
  assert.equal(fixture.issues.size, 0);
});

void test("dehydration detects integer overflow even when an adapter accepts the destination", async () => {
  const { image, issues } = createFunctionEntryFixture(new Uint8Array());
  image.isMappedRange = () => true;

  assert.deepEqual(await readNativeAotDehydratedRuns(image,
    { type: 207, rva: Number.MAX_SAFE_INTEGER - 4, size: 5 }, Uint8Array.of(0, 0, 0, 0, 65), issues), []);
  assert.deepEqual([...issues], ["DehydratedData destination is outside mapped memory."]);
});

void test("inline relocation truncation is caught before any partial operands are read", async () => {
  const { image, issues } = createFunctionEntryFixture(new Uint8Array());

  assert.deepEqual(await readNativeAotDehydratedRuns(image, { type: 207, rva: 0x180, size: 8 },
    Uint8Array.of(0, 0, 0, 0, 13, 0, 0, 0), issues), []);
  assert.deepEqual([...issues], ["DehydratedData stream is truncated."]);
});

void test("dehydration checks lookup fixups, including incomplete reads and I/O exceptions", async () => {
  const { image, issues } = createFunctionEntryFixture(new Uint8Array());
  const section = { type: 207, rva: 0x180, size: 5 };
  image.readData = async () => new DataView(new ArrayBuffer(3));

  assert.deepEqual(await readNativeAotDehydratedRuns(image, section, Uint8Array.of(0, 0, 0, 0, 3), issues), []);
  image.readData = async () => { throw "untyped I/O error"; };
  assert.deepEqual(await readNativeAotDehydratedRuns(image, section, Uint8Array.of(0, 0, 0, 0, 3), issues), []);
  assert.match([...issues].join(" "), /fixup is truncated/);
  assert.match([...issues].join(" "), /stream read failed/);
});

void test("lookup relative relocations remain data and do not become instruction roots", async () => {
  const { image, issues } = createFunctionEntryFixture(new Uint8Array());
  image.readData = async () => new DataView(Uint8Array.of(4, 0, 0, 0).buffer);

  assert.deepEqual(await readNativeAotDehydratedRuns(image, { type: 207, rva: 0x180, size: 5 },
    Uint8Array.of(0, 0, 0, 0, 2), issues), [{ kind: "relative", rva: 0x180, size: 4, target: 0x189 }]);
});
