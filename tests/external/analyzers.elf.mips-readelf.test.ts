import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { probeWslReadelf } from "./elf-wsl-readelf-fixtures.js";

for (const target of ["mips-linux-gnu", "mips64-linux-gnuabi64"]) {
  void test(`MIPS ABI metadata matches WSL clang/readelf for ${target}`, async context => {
    const probe = probeWslReadelf();
    if (!probe.available) return context.skip(probe.reason);
    const path = execFileSync("wsl", ["--exec", "mktemp", "/tmp/binary101-mips-XXXXXXXX"],
      { encoding: "utf8" }).trim();
    assert.match(path, /^\/tmp\/binary101-mips-[a-zA-Z0-9]+$/);
    try {
      execFileSync("wsl", ["--exec", "clang", `--target=${target}`, "-x", "c", "-c", "-o", path, "-"],
        { input: "int add(int left, int right) { return left + right; }\n" });
      const bytes = execFileSync("wsl", ["--exec", "cat", path]);
      const dump = execFileSync("wsl", ["--exec", "readelf", "-AW", path], { encoding: "utf8" });
      const parsed = await parseElf(new File([bytes], "mips.o"));
      const records = parsed?.mips ?? [];
      assert.ok(records.length >= 2);
      assert.deepEqual(records.flatMap(record => record.issues), []);
      const flags = records.find(record => record.abiFlags)?.abiFlags;
      assert.ok(flags);
      assert.equal(flags.version, 0);
      assert.equal(flags.isaLevel, Number(dump.match(/ISA: MIPS(\d+)/)![1]));
      assert.equal(flags.isaRevision, Number(dump.match(/ISA: MIPS\d+r(\d+)/)![1]));
      assert.equal([0, 32, 64, 128][flags.gprSize], Number(dump.match(/GPR size: (\d+)/)![1]));
      assert.ok(records.some(record => record.registerInfo || record.options?.some(option => option.registerInfo)));
    } finally {
      execFileSync("wsl", ["--exec", "rm", "-f", "--", path]);
    }
  });
}
