import assert from "node:assert/strict";
import { test } from "node:test";
import { readDModuleTable } from "../../../../analyzers/pe/d-runtime-table.js";
import { D_TEST_ABI } from "../../../fixtures/d-runtime.js";
import {
  createFragmentedDTableFixture, createPaddedPeDRuntimeFixture, createPeDRuntimeFixture
} from "../../../fixtures/pe-d-runtime.js";

for (const pointerSize of [D_TEST_ABI.pointer32Bytes, D_TEST_ABI.pointer64Bytes]) {
  void test(`reads cached tables with ${pointerSize}-byte pointers, skipping NULL padding`, async () => {
    const fixture = createPeDRuntimeFixture(pointerSize);
    const warnings: string[] = [];

    assert.deepEqual(await Array.fromAsync(readDModuleTable(fixture.file, fixture.reader,
      fixture.tableSection, fixture.module.image, warnings)),
    [fixture.module.record.address, fixture.module.record.address]);
    assert.deepEqual(warnings, []);
  });
}

void test("preserves pointers split across streamed chunks", async () => {
  const fixture = await createFragmentedDTableFixture();
  const warnings: string[] = [];

  assert.deepEqual(await Array.fromAsync(readDModuleTable(fixture.file, fixture.reader,
    fixture.tableSection, fixture.module.image, warnings)),
  [fixture.module.record.address, fixture.second.record.address]);
  assert.deepEqual(warnings, []);
});

void test("reports premature EOF in a streamed table", async () => {
  const fixture = createPaddedPeDRuntimeFixture();
  fixture.tableSection.virtualSize = fixture.tableSection.sizeOfRawData += fixture.module.image.pointerSize;
  const warnings: string[] = [];

  assert.deepEqual(await Array.fromAsync(readDModuleTable(fixture.file, fixture.reader,
    fixture.tableSection, fixture.module.image, warnings)),
  [fixture.module.record.address, fixture.second.record.address]);
  assert.match(warnings.join(" "), /truncated/);
});

void test("reports a partial pointer at the end of a streamed table", async () => {
  const fixture = createPaddedPeDRuntimeFixture();
  fixture.tableSection.virtualSize -= 1;
  const warnings: string[] = [];

  assert.deepEqual(await Array.fromAsync(readDModuleTable(fixture.file, fixture.reader,
    fixture.tableSection, fixture.module.image, warnings)), [fixture.module.record.address]);
  assert.match(warnings.join(" "), /incomplete pointer/);
});

void test("cancels a stream when the consumer rejects a candidate early", async () => {
  const fixture = await createFragmentedDTableFixture();
  const pointers = readDModuleTable(fixture.file, fixture.reader,
    fixture.tableSection, fixture.module.image, []);

  assert.equal((await pointers.next()).value, fixture.module.record.address);
  await pointers.return(undefined);

  assert.equal(fixture.wasCancelled(), true);
});

void test("reports an empty streamed table against a nonempty declared size", async () => {
  const fixture = await createFragmentedDTableFixture();
  fixture.chunks.length = 0;
  const warnings: string[] = [];

  assert.deepEqual(await Array.fromAsync(readDModuleTable(fixture.file, fixture.reader,
    fixture.tableSection, fixture.module.image, warnings)), []);
  assert.match(warnings.join(" "), /truncated/);
});

void test("stops on an empty stream chunk instead of retrying indefinitely", async () => {
  const fixture = await createFragmentedDTableFixture();
  fixture.chunks.splice(0, fixture.chunks.length, new Uint8Array(0));
  const warnings: string[] = [];

  assert.deepEqual(await Array.fromAsync(readDModuleTable(fixture.file, fixture.reader,
    fixture.tableSection, fixture.module.image, warnings)), []);
  assert.match(warnings.join(" "), /truncated/);
});

// Invalid JavaScript offsets/sizes must be rejected before Blob.slice can reinterpret them.
for (const invalid of [-1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
  void test(`rejects invalid table offset ${invalid}`, async () => {
    const fixture = createPeDRuntimeFixture();
    fixture.tableSection.pointerToRawData = invalid;
    const warnings: string[] = [];

    assert.deepEqual(await Array.fromAsync(readDModuleTable(fixture.file, fixture.reader,
      fixture.tableSection, fixture.module.image, warnings)), []);
    assert.match(warnings.join(" "), /invalid file range/);
  });
  void test(`rejects invalid table size ${invalid}`, async () => {
    const fixture = createPeDRuntimeFixture();
    fixture.tableSection.virtualSize = fixture.tableSection.sizeOfRawData = invalid;
    const warnings: string[] = [];

    assert.deepEqual(await Array.fromAsync(readDModuleTable(fixture.file, fixture.reader,
      fixture.tableSection, fixture.module.image, warnings)), []);
    assert.match(warnings.join(" "), /invalid file range/);
  });
}
