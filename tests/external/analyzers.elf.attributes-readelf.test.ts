import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { probeWslReadelf } from "./elf-wsl-readelf-fixtures.js";

for (const target of ["armv7-none-eabi", "riscv64-none-elf"]) {
  void test(`architecture attributes match WSL clang/readelf for ${target}`, async context => {
    const probe = probeWslReadelf();
    if (!probe.available) return context.skip(probe.reason);
    const path = execFileSync("wsl", ["--exec", "mktemp", "/tmp/binary101-attributes-XXXXXXXX"],
      { encoding: "utf8" }).trim();
    assert.match(path, /^\/tmp\/binary101-attributes-[a-zA-Z0-9]+$/);
    try {
      execFileSync("wsl", ["--exec", "clang", `--target=${target}`, "-x", "c", "-c", "-o", path, "-"],
        { input: "int add(int left, int right) { return left + right; }\n" });
      const bytes = execFileSync("wsl", ["--exec", "cat", path]);
      const dump = execFileSync("wsl", ["--exec", "readelf", "-AW", path], { encoding: "utf8" });
      const parsed = await parseElf(new File([bytes], "attributes.o"));
      assert.equal(parsed?.attributes?.length, 1);
      const section = parsed.attributes[0]!;
      assert.deepEqual(section.issues, []);
      const vendor = section.vendors[0]!;
      const values = new Map(vendor.scopes[0]!.attributes.map(attribute => [attribute.tag, attribute.value]));
      if (target.startsWith("arm")) {
        assert.equal(vendor.name, "aeabi");
        assert.equal(values.get(6n), 10n); // ARM Tag_CPU_arch value 10 is v7.
        assert.match(dump, /Tag_CPU_arch: v7/);
        assert.equal(values.get(5n), dump.match(/Tag_CPU_name: "([^"]+)"/)?.[1]);
      } else {
        assert.equal(vendor.name, "riscv");
        assert.equal(values.get(4n), BigInt(dump.match(/Tag_RISCV_stack_align: (\d+)/)![1]!));
        assert.equal(values.get(5n), dump.match(/Tag_RISCV_arch: "([^"]+)"/)?.[1]);
      }
    } finally {
      execFileSync("wsl", ["--exec", "rm", "-f", "--", path]);
    }
  });
}
