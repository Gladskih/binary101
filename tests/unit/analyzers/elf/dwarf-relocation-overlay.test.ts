import assert from "node:assert/strict";
import { test } from "node:test";
import { elfDwarfRelocationOverlay } from "../../../../analyzers/elf/dwarf-relocation-overlay.js";
import { createDwarfRelocationFixture } from "../../../fixtures/dwarf-relocation-fixture.js";

void test("relocation overlays merge partial reads at every field boundary", async () => {
  const { source } = createDwarfRelocationFixture();
  const overlay = elfDwarfRelocationOverlay(source.reader,
    [{ offset: 10, bytes: Uint8Array.of(5, 6) }, { offset: 4, bytes: Uint8Array.of(1, 2, 3, 4) }]);

  assert.deepEqual(Array.from(await overlay.readBytes(3, 9)), [0, 1, 2, 3, 4, 0, 0, 5, 6]);
  assert.deepEqual(Array.from(await overlay.readBytes(5, 2)), [2, 3]);
  assert.deepEqual(Array.from(await overlay.readBytes(7, 2)), [4, 0]);
  assert.deepEqual(Array.from(await overlay.readBytes(8, 2)), [0, 0]);
  assert.deepEqual(Array.from(await overlay.readBytes(11, 5)), [6, 0, 0, 0, 0]);
  assert.deepEqual(Array.from(await overlay.readBytes(12, 4)), [0, 0, 0, 0]);
  assert.deepEqual(Array.from(await source.reader.readBytes(4, 4)), [0, 0, 0, 0]);
});

void test("empty overlays preserve bounded original reads", async () => {
  const { source } = createDwarfRelocationFixture();
  const overlay = elfDwarfRelocationOverlay(source.reader, []);

  assert.equal((await overlay.read(16, 4)).byteLength, 0);
  assert.equal((await overlay.read(0, 4)).byteLength, 4);
});
