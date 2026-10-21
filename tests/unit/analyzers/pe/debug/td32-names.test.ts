import assert from "node:assert/strict";
import { test } from "node:test";
import { readTd32Names } from "../../../../../analyzers/pe/debug/td32-names.js";
import { td32Names } from "../../../../fixtures/pe-td32.js";
import { legacyReader, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

void test("TD32 names preserve empty names and lengths larger than a byte", async () => {
  const names = ["", "A".repeat(256), "B".repeat(511)];
  const warnings: string[] = [];

  assert.deepEqual(await readTd32Names(legacyReader(td32Names(names), warnings)), { kind: "names", names });
  assert.deepEqual(await readTd32Names(legacyReader(legacyU32(0))), { kind: "names", names: [] });
  assert.deepEqual(warnings, []);
});

void test("TD32 stops exactly at its declared name count even with extra stored strings", async () => {
  const bytes = td32Names(["first", "unused"]);
  bytes[0] = 1;
  const warnings: string[] = [];

  assert.deepEqual((await readTd32Names(legacyReader(bytes, warnings))).names, ["first"]);
  assert.deepEqual(warnings, []);
  assert.deepEqual((await readTd32Names(legacyReader(td32Names(["", ""]), warnings))).names, ["", ""]);
  assert.deepEqual(warnings, []);
});

void test("TD32 rejects impossible minimum-size counts before attempting individual strings", async () => {
  const warnings: string[] = [];

  await readTd32Names(legacyReader([...legacyU32(2), 0, 0, 0], warnings));

  assert.match(warnings.join(" | "), /count exceeds available bytes/);
});

void test("TD32 malformed names retain preceding strings and report inconsistent lengths", async () => {
  const warnings: string[] = [];
  const bytes = td32Names(["first", "second"]);
  bytes[4] = 9;

  const parsed = await readTd32Names(legacyReader(bytes.subarray(0, bytes.length - 1), warnings));

  assert.deepEqual(parsed.names, ["first"]);
  assert.match(warnings.join(" | "), /length disagrees/);
  assert.match(warnings.join(" | "), /NUL-terminated/);
  assert.match(warnings.join(" | "), /table is truncated/);
  await assert.rejects(readTd32Names(legacyReader([])), /bounds/);
});

void test("TD32 does not allocate from claimed name counts or invent missing strings", async () => {
  const warnings: string[] = [];

  const parsed = await readTd32Names(legacyReader(legacyU32(0xffffffff), warnings));

  assert.deepEqual(parsed.names, []);
  assert.deepEqual(warnings, ["TD32 name count exceeds available bytes.", "TD32 names table is truncated."]);
});

void test("TD32 UTF-8 names remain readable and ANSI fallback is explicitly warned", async () => {
  const warnings: string[] = [];
  const bytes = td32Names(["имя", "é"]);
  bytes[bytes.length - 3] = 0x80;

  const parsed = await readTd32Names(legacyReader(bytes, warnings));

  assert.equal(parsed.names[0], "имя");
  assert.equal(parsed.names[1], "€©");
  assert.equal(warnings.filter(warning => /invalid UTF-8/.test(warning)).length, 1);
});
