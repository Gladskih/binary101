import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { DwarfCursor } from "../../../../analyzers/dwarf/cursor.js";
import { readElfBuildAttribute } from "../../../../analyzers/elf/attribute-values.js";

const read = async (bytes: number[], vendor = "aeabi") => {
  const file = new File([new Uint8Array(bytes)], "attributes");
  const issues: string[] = [];
  const cursor = new DwarfCursor(createFileRangeReader(file, 0, file.size),
    { name: "attributes", offset: 0, size: file.size, compressed: false }, 0, file.size, true, issues);
  return { attribute: await readElfBuildAttribute(cursor, vendor), issues };
};

void test("reads ARM's exceptional string tags and odd extension tags", async () => {
  assert.deepEqual((await read([4, 65, 0])).attribute, { tag: 4n, value: "A" });
  assert.deepEqual((await read([67, 66, 0])).attribute, { tag: 67n, value: "B" });
  assert.deepEqual((await read([7, 65])).attribute, { tag: 7n, value: 65n });
  assert.deepEqual((await read([64, 1])).attribute, { tag: 64n, value: 1n });
});

void test("reports missing tags and incomplete compatibility payloads", async () => {
  assert.equal((await read([])).attribute, null);
  assert.equal((await read([32])).attribute, null);
  assert.equal((await read([32, 1, 65])).attribute, null);
  assert.equal((await read([4, 65])).attribute, null);
});

void test("reports unknown mandatory RISC-V tags but preserves their values", async () => {
  const result = await read([7, 65, 0], "riscv");
  assert.deepEqual(result.attribute, { tag: 7n, value: "A" });
  assert.match(result.issues.join(" "), /mandatory/);
  assert.deepEqual((await read([64, 1], "riscv")).issues, []);
});
