import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { probeWslReadelf } from "./elf-wsl-readelf-fixtures.js";

void test("reads real compiler LSDA call sites and catch-all action in WSL", async context => {
  const probe = probeWslReadelf();
  if (!probe.available) return context.skip(probe.reason);
  const path = execFileSync("wsl", ["--exec", "mktemp", "/tmp/binary101-lsda-XXXXXXXX"],
    { encoding: "utf8" }).trim();
  assert.match(path, /^\/tmp\/binary101-lsda-[a-zA-Z0-9]+$/);
  try {
    execFileSync("wsl", ["--exec", "clang++", "-x", "c++", "-o", path, "-"],
      { input: "__attribute__((noinline)) int fail() { throw 42; }\n" +
        "int main() { try { return fail(); } catch (...) { return 0; } }\n" });
    const bytes = execFileSync("wsl", ["--exec", "cat", path]);
    const dump = execFileSync("wsl", ["--exec", "readelf", "-SW", path], { encoding: "utf8" });
    const parsed = await parseElf(new File([bytes], "lsda"));
    assert.match(dump, /\.gcc_except_table/);
    assert.ok(parsed?.lsdas?.length);
    assert.deepEqual(parsed.lsdas.flatMap(lsda => lsda.issues), []);
    assert.ok(parsed.lsdas.some(lsda => lsda.callSites.some(site => site.landingPad > 0n && site.action > 0n)));
    assert.ok(parsed.lsdas.some(lsda => lsda.actions.some(action => action.typeFilter > 0n)));
    assert.ok(parsed.lsdas.some(lsda => lsda.types.some(type => type.pointer?.address === 0n)));
    execFileSync("wsl", ["--exec", path]);
  } finally {
    execFileSync("wsl", ["--exec", "rm", "-f", "--", path]);
  }
});
