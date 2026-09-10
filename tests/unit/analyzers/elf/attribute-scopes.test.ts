import assert from "node:assert/strict";
import { test } from "node:test";
import { DwarfCursor } from "../../../../analyzers/dwarf/cursor.js";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { readElfAttributeVendor } from "../../../../analyzers/elf/attribute-scopes.js";

const read = async (payload: number[], scopeTag = 2, vendor = "aeabi") => {
  const name = new TextEncoder().encode(`${vendor}\0`);
  const bytes = new Uint8Array(4 + name.length + 5 + payload.length);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, bytes.length, true);
  bytes.set(name, 4);
  bytes[4 + name.length] = scopeTag;
  view.setUint32(5 + name.length, 5 + payload.length, true);
  bytes.set(payload, 9 + name.length);
  const file = new File([bytes], "attributes");
  const issues: string[] = [];
  const reader = createFileRangeReader(file, 0, file.size);
  const cursorAt = (start: number, end: number) => new DwarfCursor(reader,
    { name: "attributes", offset: 0, size: file.size, compressed: false }, start, end, true, issues);
  return { vendor: await readElfAttributeVendor(cursorAt(0, file.size), cursorAt), issues };
};

void test("preserves section and symbol scope index lists", async () => {
  assert.deepEqual((await read([3, 7, 0, 6, 10])).vendor?.scopes[0], {
    tag: 2n, indices: [3n, 7n], attributes: [{ tag: 6n, value: 10n }]
  });
  assert.deepEqual((await read([4, 0, 6, 10], 3)).vendor?.scopes[0]?.indices, [4n]);
});

void test("reports unknown scopes and vendors and missing index terminators", async () => {
  assert.match((await read([], 4)).issues.join(" "), /scope/);
  assert.match((await read([], 1, "custom")).issues.join(" "), /vendor/);
  assert.match((await read([3, 7])).issues.join(" "), /truncated|Unexpected|Cannot/i);
});
