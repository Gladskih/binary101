import assert from "node:assert/strict";
import test from "node:test";
import { findNativeAotHydratedRun, readNativeAotHydratedUnsigned } from
  "../../../../analyzers/native-aot/hydrated-scalars.js";
import { createNativeAotRuntimeTypeFixture } from "../../../helpers/native-aot-runtime-type-fixture.js";

void test("reads fixed scalars across copied and zero-filled run boundaries", async () => {
  const fixture = createNativeAotRuntimeTypeFixture();
  const sourceRva = fixture.bytes.length - fixture.image.pointerSize;
  fixture.view.setUint8(sourceRva, 7); // Incidental replacement byte.
  const runs = [{ kind: "zero", rva: fixture.typeRva + 1, size: 1 },
    { kind: "copy", rva: fixture.typeRva + 2, size: 1, sourceRva }] as const;

  // EETypeElementType.Class=0x14 in bits 26..30; overlay byte two in little-endian order.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/MethodTable.Constants.cs
  assert.equal(await readNativeAotHydratedUnsigned(fixture.image, [...runs], fixture.typeRva, 4),
    (0x14 << 26) | (7 << (2 * 8)));
  assert.equal(await readNativeAotHydratedUnsigned(fixture.image, [], fixture.typeRva + 4, 2), 24);
  assert.equal(findNativeAotHydratedRun([...runs], fixture.typeRva + 3), undefined);
  assert.equal(findNativeAotHydratedRun([...runs], fixture.typeRva), undefined);
  assert.equal(findNativeAotHydratedRun([...runs], fixture.typeRva + 2), runs[1]);
});

void test("rejects invalid coordinates and typed pointer runs instead of interpreting their bytes", async () => {
  const fixture = createNativeAotRuntimeTypeFixture();

  await assert.rejects(readNativeAotHydratedUnsigned(fixture.image, [], -1, 2), /invalid mapped range/);
  await assert.rejects(readNativeAotHydratedUnsigned(fixture.image, [], fixture.bytes.length, 2), /invalid mapped range/);
  await assert.rejects(readNativeAotHydratedUnsigned(fixture.image, [], NaN, 2), /invalid mapped range/);
  await assert.rejects(readNativeAotHydratedUnsigned(fixture.image, [], 0, 1 as 2), /invalid mapped range/);
  await assert.rejects(readNativeAotHydratedUnsigned(fixture.image,
    [{ kind: "pointer", rva: fixture.typeRva, size: fixture.image.pointerSize,
      target: fixture.codeRvas[0]! }], fixture.typeRva, 4), /overlaps/);
});

void test("reports missing and truncated scalar bytes", async context => {
  const fixture = createNativeAotRuntimeTypeFixture();
  context.mock.method(fixture.image, "readData", async () => null);

  await assert.rejects(readNativeAotHydratedUnsigned(fixture.image, [], 0, 2), /unreadable/);
  context.mock.method(fixture.image, "readData", async () => new DataView(new ArrayBuffer(0)));
  await assert.rejects(readNativeAotHydratedUnsigned(fixture.image, [], 0, 2), /truncated/);
});

void test("validates coordinates even if a container mapping reports them mapped", async context => {
  const fixture = createNativeAotRuntimeTypeFixture();
  context.mock.method(fixture.image, "isMappedRange", () => true);

  await assert.rejects(readNativeAotHydratedUnsigned(fixture.image, [], -1, 2), /invalid mapped range/);
  await assert.rejects(readNativeAotHydratedUnsigned(fixture.image, [], NaN, 2), /invalid mapped range/);
});
