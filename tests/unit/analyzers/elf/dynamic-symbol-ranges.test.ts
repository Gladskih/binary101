import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfDynamicSymbols } from "../../../../analyzers/elf/dynamic-symbols.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";

for (const offset of [-1n, 1024n, 1n << 60n]) {
  void test(`rejects dynamic symbol file offset ${offset}`, async () => {
    const fixture = relocationFixture();
    fixture.elf.sections[2]!.type = 11;
    fixture.elf.sections[2]!.offset = offset;
    const result = await parseElfDynamicSymbols({ ...fixture.elf, file: fixture.file() });
    assert.deepEqual(result?.exportSymbols, []);
    assert.match(result!.issues.join(" "), /outside the file/);
  });
}

void test("retains complete symbols from a truncated or partial table", async () => {
  const fixture = relocationFixture();
  fixture.elf.sections[2]!.type = 11;
  fixture.elf.sections[2]!.offset = 1000n;
  fixture.elf.sections[2]!.size = 25n;
  const result = await parseElfDynamicSymbols({ ...fixture.elf, file: fixture.file() });
  assert.equal(result?.total, 1);
  assert.match(result!.issues.join(" "), /truncated/);
  fixture.elf.sections[2]!.offset = 999n;
  const partial = await parseElfDynamicSymbols({ ...fixture.elf, file: fixture.file() });
  assert.equal(partial?.total, 1);
  assert.match(partial!.issues.join(" "), /aligned/);
});

for (const [count, exceedsLimit] of [[1000000, false], [1000001, true]] as const) {
  void test(`bounds dynamic symbols at the resource limit ${count}`, async () => {
    const fixture = relocationFixture();
    fixture.elf.sections[2]!.type = 11;
    fixture.elf.sections[2]!.size = BigInt(count) * 24n; // Elf64_Sym, gABI 5.
    const file = new File([], "short-read");
    // Simulate a file becoming unreadable without allocating a million symbols.
    Object.defineProperty(file, "size", { value: 256 + count * 24 });
    const result = await parseElfDynamicSymbols({ ...fixture.elf, file });
    assert.equal(result?.total, count);
    assert.deepEqual(result?.exportSymbols, []);
    assert.match(result!.issues.join(" "), /symbol #0 is truncated/);
    assert.equal(result?.issues.some(issue => issue.includes("resource limit")), exceedsLimit);
  });
}
