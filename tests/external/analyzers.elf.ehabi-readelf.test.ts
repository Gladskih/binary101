import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { probeWslReadelf } from "./elf-wsl-readelf-fixtures.js";

void test("ARM EHABI programs match real WSL clang/readelf object output", async context => {
  const probe = probeWslReadelf();
  if (!probe.available) return context.skip(probe.reason);
  const path = execFileSync("wsl", ["--exec", "mktemp", "/tmp/binary101-ehabi-XXXXXXXX"],
    { encoding: "utf8" }).trim();
  assert.match(path, /^\/tmp\/binary101-ehabi-[a-zA-Z0-9]+$/);
  try {
    execFileSync("wsl", ["--exec", "clang", "--target=armv7-none-eabi", "-funwind-tables",
      "-x", "c", "-c", "-o", path, "-"],
    { input: "int add(int left, int right) { return left + right; }\n" });
    const bytes = execFileSync("wsl", ["--exec", "cat", path]);
    const dump = execFileSync("wsl", ["--exec", "readelf", "-uW", path], { encoding: "utf8" });
    const parsed = await parseElf(new File([bytes], "ehabi.o"));
    assert.equal(parsed?.armEhabi?.length, 1);
    const table = parsed.armEhabi[0]!;
    assert.deepEqual(table.issues, []);
    assert.equal(table.entries.length, Number(dump.match(/contains (\d+) entr/)![1]));
    assert.equal(table.entries[0]?.personality, 0);
    assert.match(dump, /Compact model index: 0/);
    assert.match(dump, /vsp = vsp \+ 8/);
    assert.equal(table.entries[0]?.instructions[0]?.text, "vsp += 8");
    assert.equal(table.entries[0]?.functionAddress, null);
    assert.match(table.entries[0]!.issues.join(" "), /relocations/);
  } finally {
    execFileSync("wsl", ["--exec", "rm", "-f", "--", path]);
  }
});
