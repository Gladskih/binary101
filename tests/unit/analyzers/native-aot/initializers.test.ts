import assert from "node:assert/strict";
import { test } from "node:test";
import { parseNativeAotInitializers } from "../../../../analyzers/native-aot/initializers.js";
import { createNativeAotInitializerFixture, createChunkedInitializerFixture } from
  "../../../helpers/native-aot-initializer-fixture.js";

// Independent oracles for the analyzer's documented resource policy, not format constants.
const TABLE_LIMIT_BYTES = 1024 * 1024;
const READ_CHUNK_BYTES = 4096;

// ModuleHeaders.cs: EagerCctor = 205, ModuleInitializerList = 213.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/ModuleHeaders.cs
for (const type of [205, 213]) {
  void test(`decodes initializer section ${type} with signed slot-relative targets`, async () => {
    const fixture = createNativeAotInitializerFixture();
    fixture.header.sections[0]!.type = type;

    const result = await parseNativeAotInitializers(fixture.image, fixture.header);

    assert.deepEqual(result, [{ sectionType: type, targetRvas: fixture.codeRvas, warnings: [] }]);
  });
}

void test("supports the verified .NET 9 format and x86 relative pointers", async () => {
  const fixture = createNativeAotInitializerFixture(4); // x86 native pointer width in bytes.
  // .NET 9 uses header version 10.1.
  // https://github.com/dotnet/runtime/blob/v9.0.0/src/coreclr/tools/Common/Internal/Runtime/ModuleHeaders.cs
  fixture.header.majorVersion = 10;
  fixture.header.minorVersion = 1;

  const result = await parseNativeAotInitializers(fixture.image, fixture.header);

  assert.deepEqual(result[0]?.targetRvas, fixture.codeRvas);
});

// .NET 8 version 9.1 permits an ambiguous CppCodegen ABI; 10.0 and 16.1 differ from
// supported release versions only in the minor field; 0xffff is an unverified uint16 major.
// https://github.com/dotnet/runtime/blob/v8.0.0/src/coreclr/tools/Common/Internal/Runtime/ModuleHeaders.cs
for (const [majorVersion, minorVersion] of [[9, 1], [10, 0], [16, 1], [0xffff, 0]] as const) {
  void test(`rejects unverified version ${majorVersion}.${minorVersion}`, async () => {
    const fixture = createNativeAotInitializerFixture();

    const result = await parseNativeAotInitializers(fixture.image, {
      ...fixture.header, majorVersion, minorVersion
    });

    assert.deepEqual(result[0]?.targetRvas, []);
    assert.match(result[0]?.warnings.join(" ") ?? "", /version/i);
  });
}

for (const [name, size] of [
  ["unknown extent", null],
  ["negative extent", -Int32Array.BYTES_PER_ELEMENT],
  ["single byte", 1],
  ["incomplete int32 entry", Int32Array.BYTES_PER_ELEMENT - 1],
  ["NaN extent", NaN],
  ["fractional byte count", Int32Array.BYTES_PER_ELEMENT + 0.5],
  ["extreme extent", Number.MAX_SAFE_INTEGER],
  ["one entry over resource limit", TABLE_LIMIT_BYTES + Int32Array.BYTES_PER_ELEMENT]
] as const) {
  void test(`rejects initializer table with ${name}`, async () => {
    const fixture = createNativeAotInitializerFixture();
    fixture.header.sections[0]!.size = size;

    const result = await parseNativeAotInitializers(fixture.image, fixture.header);

    assert.deepEqual(result[0]?.targetRvas, []);
    assert.deepEqual(result[0]?.warnings,
      ["Initializer table has an unknown, invalid, or excessive byte size."]);
  });
}

void test("ignores unrelated sections", async () => {
  const fixture = createNativeAotInitializerFixture();
  // ReflectionMapBlob.CommonFixupsTable = 8, with the section ID offset of 300.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/MetadataBlob.cs
  fixture.header.sections[0]!.type = 308;

  assert.deepEqual(await parseNativeAotInitializers(fixture.image, fixture.header), []);
});

void test("accepts an empty table", async () => {
  const fixture = createNativeAotInitializerFixture();
  fixture.header.sections[0]!.size = 0;

  const result = await parseNativeAotInitializers(fixture.image, fixture.header);

  assert.deepEqual(result[0]?.targetRvas, []);
  assert.deepEqual(result[0]?.warnings, []);
});

void test("rejects a table outside file-backed data", async () => {
  const fixture = createNativeAotInitializerFixture();
  fixture.image.isDataRange = () => false;

  const result = await parseNativeAotInitializers(fixture.image, fixture.header);

  assert.deepEqual(result[0]?.targetRvas, []);
  assert.deepEqual(result[0]?.warnings,
    ["Initializer table is not aligned, fully file-backed data."]);
});

for (const readData of [async () => null,
  async () => new DataView(new ArrayBuffer(Int32Array.BYTES_PER_ELEMENT - 1))]) {
  void test("reports unreadable data or an incomplete int32 without throwing", async () => {
    const fixture = createNativeAotInitializerFixture();
    fixture.image.readData = readData;

    const result = await parseNativeAotInitializers(fixture.image, fixture.header);

    assert.deepEqual(result[0]?.targetRvas, []);
    assert.deepEqual(result[0]?.warnings, ["Initializer table is truncated or unreadable."]);
  });
}

void test("reports a reader exception visibly", async () => {
  const fixture = createNativeAotInitializerFixture();
  fixture.image.readData = async () => { throw new Error("I/O"); };

  const result = await parseNativeAotInitializers(fixture.image, fixture.header);

  assert.deepEqual(result[0]?.warnings, ["Initializer table could not be read."]);
  assert.deepEqual(result[0]?.targetRvas, []);
});

void test("discards a whole table when a later target is not executable", async () => {
  const fixture = createNativeAotInitializerFixture();
  fixture.image.isExecutableAddress = address => address === fixture.codeRvas[0];

  const result = await parseNativeAotInitializers(fixture.image, fixture.header);

  assert.deepEqual(result[0]?.targetRvas, []);
  assert.match(result[0]?.warnings.join(" ") ?? "", /executable/i);
});

void test("reads the maximum accepted table in bounded chunks", async () => {
  const reads: number[] = [];
  const fixture = createChunkedInitializerFixture(TABLE_LIMIT_BYTES, reads);

  const result = await parseNativeAotInitializers(fixture.image, fixture.header);

  assert.deepEqual(result[0]?.targetRvas, [fixture.codeRvas[0]]);
  assert.equal(reads.length, TABLE_LIMIT_BYTES / READ_CHUNK_BYTES);
  assert.equal(Math.max(...reads), READ_CHUNK_BYTES);
});

void test("limits the last chunk to the exact remaining bytes", async () => {
  const reads: number[] = [];
  const fixture = createChunkedInitializerFixture(READ_CHUNK_BYTES + Int32Array.BYTES_PER_ELEMENT, reads);

  await parseNativeAotInitializers(fixture.image, fixture.header);

  assert.deepEqual(reads, [READ_CHUNK_BYTES, Int32Array.BYTES_PER_ELEMENT]);
});

void test("a broken table does not suppress another valid initializer table", async () => {
  const fixture = createNativeAotInitializerFixture();
  // ModuleHeaders.cs ModuleInitializerList = 213; see the independent section-ID oracle above.
  fixture.header.sections.push({ ...fixture.header.sections[0]!, type: 213 });
  fixture.header.sections[0]!.size = null;

  const result = await parseNativeAotInitializers(fixture.image, fixture.header);

  assert.deepEqual(result[0]?.targetRvas, []);
  assert.deepEqual(result[1]?.targetRvas, fixture.codeRvas);
});
