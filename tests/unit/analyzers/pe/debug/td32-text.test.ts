import assert from "node:assert/strict";
import { test } from "node:test";
import { readTd32Text } from "../../../../../analyzers/pe/debug/td32-text.js";
import { legacyReader } from "../../../../fixtures/pe-legacy-codeview.js";

void test("TD32 UTF-8 names preserve multibyte characters across windows and retain BOMs", async () => {
  const name = "A".repeat(255) + "😀имя";
  const bytes = new TextEncoder().encode(name);

  assert.deepEqual(await readTd32Text(legacyReader([...bytes, 0]), 0),
    { name, end: bytes.length + 1, encoding: "UTF-8" });
  assert.deepEqual(await readTd32Text(legacyReader([0]), 0), { name: "", end: 1, encoding: "UTF-8" });
  assert.equal((await readTd32Text(legacyReader([0xef, 0xbb, 0xbf, 65, 0]), 0)).name, "\ufeffA");
});

void test("TD32 ANSI fallback retains invalid and incomplete UTF-8 without rereading", async () => {
  assert.deepEqual(await readTd32Text(legacyReader([0x80, 65, 0]), 0),
    { name: "€A", end: 3, encoding: "Windows-1252" });
  assert.deepEqual(await readTd32Text(legacyReader([0xc3, 0]), 0),
    { name: "Ã", end: 2, encoding: "Windows-1252" });
  assert.equal((await readTd32Text(legacyReader([0x80, ...new Array<number>(300).fill(65), 0]), 0)).name,
    "€" + "A".repeat(300));
  await assert.rejects(readTd32Text(legacyReader([65]), 0), /NUL-terminated/);
});
