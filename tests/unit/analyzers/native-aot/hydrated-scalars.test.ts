import assert from "node:assert/strict";
import test from "node:test";
import { findNativeAotHydratedRun, readNativeAotHydratedUnsigned } from
  "../../../../analyzers/native-aot/hydrated-scalars.js";
import { createNativeAotRuntimeTypeFixture } from "../../../helpers/native-aot-runtime-type-fixture.js";

void test("reads fixed scalars across copied and zero-filled run boundaries", async () => {
  const fixture = createNativeAotRuntimeTypeFixture();
  fixture.view.setUint8(0x380, 7);
  const runs = [{ kind: "zero", rva: 0x181, size: 1 },
    { kind: "copy", rva: 0x182, size: 1, sourceRva: 0x380 }] as const;

  assert.equal(await readNativeAotHydratedUnsigned(fixture.image, [...runs], 0x180, 4), 0x4070000);
  assert.equal(await readNativeAotHydratedUnsigned(fixture.image, [], 0x184, 2), 24);
  assert.equal(findNativeAotHydratedRun([...runs], 0x183), undefined);
  assert.equal(findNativeAotHydratedRun([...runs], 0x180), undefined);
  assert.equal(findNativeAotHydratedRun([...runs], 0x182), runs[1]);
});

void test("rejects invalid coordinates and typed pointer runs instead of interpreting their bytes", async () => {
  const fixture = createNativeAotRuntimeTypeFixture();

  await assert.rejects(readNativeAotHydratedUnsigned(fixture.image, [], -1, 2), /invalid mapped range/);
  await assert.rejects(readNativeAotHydratedUnsigned(fixture.image, [], 0x400, 2), /invalid mapped range/);
  await assert.rejects(readNativeAotHydratedUnsigned(fixture.image, [], NaN, 2), /invalid mapped range/);
  await assert.rejects(readNativeAotHydratedUnsigned(fixture.image, [], 0, 1 as 2), /invalid mapped range/);
  await assert.rejects(readNativeAotHydratedUnsigned(fixture.image,
    [{ kind: "pointer", rva: 0x180, size: 8, target: 0x40 }], 0x180, 4), /overlaps/);
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
