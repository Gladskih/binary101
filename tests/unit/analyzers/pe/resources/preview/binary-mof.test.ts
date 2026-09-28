import assert from "node:assert/strict";
import { test } from "node:test";
import { addBinaryMofPreview } from "../../../../../../analyzers/pe/resources/preview/binary-mof.js";
import { compressedMofFixture, decodedMofFixture, encodeDsLiterals } from
  "../../../../../helpers/binary-mof-fixture.js";

const replaceWord = (bytes: Uint8Array, offset: number, value: number): Uint8Array => {
  const copy = bytes.slice();
  new DataView(copy.buffer).setUint32(offset, value, true);
  return copy;
};

const repack = (decoded: Uint8Array): Uint8Array => {
  const compressed = encodeDsLiterals(decoded);
  const bytes = new Uint8Array(16 + compressed.length);
  bytes.set([70, 79, 77, 66]);
  new DataView(bytes.buffer).setUint32(4, 1, true);
  new DataView(bytes.buffer).setUint32(8, compressed.length, true);
  new DataView(bytes.buffer).setUint32(12, decoded.length, true);
  bytes.set(compressed, 16);
  return bytes;
};

void test("parses a compressed FOMB resource", () => {
  const result = addBinaryMofPreview(compressedMofFixture(), "MOFDATA");
  assert.equal(result?.preview?.previewKind, "binaryMof");
  assert.equal(result?.preview.binaryMof?.classes[0]?.name, "TestClass");
  assert.equal(result?.preview.binaryMof?.flavorCount, 0);
  assert.equal(result?.issues, undefined);
});

void test("ignores unrelated resource types", () => {
  assert.equal(addBinaryMofPreview(compressedMofFixture(), "RCDATA"), null);
});

void test("reports invalid outer headers and versions", () => {
  assert.match(addBinaryMofPreview(new Uint8Array(3), "FOMB")?.issues?.join(" ") ?? "", /header/);
  assert.match(addBinaryMofPreview(replaceWord(compressedMofFixture(), 4, 2),
    "BMOF")?.issues?.join(" ") ?? "", /version/);
});

void test("reports inconsistent compressed sizes", () => {
  const resource = compressedMofFixture();
  assert.match(addBinaryMofPreview(replaceWord(resource, 8, resource.length),
    "MOFDATA")?.issues?.join(" ") ?? "", /size/);
  assert.match(addBinaryMofPreview(replaceWord(resource, 8, 0),
    "MOFDATA")?.issues?.join(" ") ?? "", /size/);
});

void test("reports invalid decompressed headers and class sizes", () => {
  const invalid = decodedMofFixture();
  invalid[0] = 0;
  assert.match(addBinaryMofPreview(repack(invalid), "MOFDATA")?.issues?.join(" ") ?? "",
    /decompressed/);
  invalid.set([70, 79, 77, 66]);
  new DataView(invalid.buffer).setUint32(4, invalid.length + 1, true);
  assert.match(addBinaryMofPreview(repack(invalid), "MOFDATA")?.issues?.join(" ") ?? "",
    /class section/);
});

void test("reports damaged qualifier-flavor trailers", () => {
  const missing = decodedMofFixture();
  missing[missing.length - 20] = 0;
  const invalidCount = decodedMofFixture();
  new DataView(invalidCount.buffer).setUint32(invalidCount.length - 4, 1, true);
  assert.match(addBinaryMofPreview(repack(missing), "MOFDATA")?.issues?.join(" ") ?? "",
    /trailer/);
  assert.match(addBinaryMofPreview(repack(invalidCount), "MOFDATA")?.issues?.join(" ") ?? "",
    /flavor records/);
});

void test("counts a valid qualifier-flavor trailer entry", () => {
  const decoded = decodedMofFixture();
  const withEntry = Uint8Array.from([...decoded.subarray(0, decoded.length - 4),
    1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
  const result = addBinaryMofPreview(repack(withEntry), "MOFDATA");
  assert.equal(result?.preview?.binaryMof?.flavorCount, 1);
  assert.equal(result?.issues, undefined);
});

void test("parses a class section without a qualifier-flavor trailer", () => {
  const decoded = decodedMofFixture();
  const firstPart = new DataView(decoded.buffer).getUint32(4, true);
  const result = addBinaryMofPreview(repack(decoded.subarray(0, firstPart)), "BMOF");
  assert.equal(result?.preview?.binaryMof?.classes[0]?.name, "TestClass");
  assert.equal(result?.preview?.binaryMof?.flavorCount, 0);
  assert.equal(result?.issues, undefined);
});

void test("checks compressed container markers and exact diagnostic fields", () => {
  const damaged = compressedMofFixture();
  damaged[0] = 0;
  const badStream = compressedMofFixture();
  badStream[16] = 0;
  const header = addBinaryMofPreview(damaged, "MOFDATA");
  const stream = addBinaryMofPreview(badStream, "MOFDATA");
  assert.deepEqual(header?.preview?.previewFields, [
    { label: "Type", value: "MOFDATA" }, { label: "Format", value: "Binary WMI MOF" }
  ]);
  assert.deepEqual(header?.issues, ["Binary MOF FOMB header is invalid or truncated."]);
  assert.deepEqual(stream?.issues, ["Binary MOF DS-01 header is invalid."]);
});

void test("rejects short but recognizable FOMB containers and class sections", () => {
  const shortOuter = new Uint8Array(15);
  shortOuter.set([70, 79, 77, 66]);
  const shortInner = Uint8Array.from([70, 79, 77, 66, 16, 0, 0, 0]);
  const invalidEnd = replaceWord(decodedMofFixture(), 4, 19);
  assert.deepEqual(addBinaryMofPreview(shortOuter, "MOFDATA")?.issues,
    ["Binary MOF FOMB header is invalid or truncated."]);
  assert.deepEqual(addBinaryMofPreview(repack(shortInner), "MOFDATA")?.issues,
    ["Binary MOF decompressed FOMB header is invalid."]);
  assert.deepEqual(addBinaryMofPreview(repack(invalidEnd), "MOFDATA")?.issues,
    ["Binary MOF class section size is invalid."]);
});

void test("reports a qualifier trailer cut short after its marker", () => {
  const decoded = decodedMofFixture();
  const damaged = decoded.subarray(0, decoded.length - 1);
  assert.deepEqual(addBinaryMofPreview(repack(damaged), "MOFDATA")?.issues,
    ["Binary MOF qualifier-flavor trailer is invalid or truncated."]);
});
