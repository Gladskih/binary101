import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { probeWslReadelf } from "./elf-wsl-readelf-fixtures.js";

void test("COMDAT groups match a real WSL libstdc++ archive member", async context => {
  const probe = probeWslReadelf();
  if (!probe.available) return context.skip(probe.reason);
  const archive = execFileSync("wsl", ["--exec", "sh", "-c",
    "find /usr/lib/gcc -name libstdc++.a | head -1"], { encoding: "utf8" }).trim();
  assert.ok(archive);
  const temporary = execFileSync("wsl", ["--exec", "mktemp", "/tmp/binary101-group-XXXXXX"],
    { encoding: "utf8" }).trim();
  try {
    execFileSync("wsl", ["--exec", "sh", "-c", 'ar p "$1" compatibility.o > "$2"',
      "sh", archive, temporary]);
    const bytes = execFileSync("wsl", ["--exec", "cat", temporary], { maxBuffer: 16 * 1024 * 1024 });
    const dump = execFileSync("wsl", ["--exec", "readelf", "-gW", temporary], { encoding: "utf8" });
    const elf = await parseElf(new File([bytes], "compatibility.o"));
    assert.ok(elf?.sectionGroups?.length);
    const expected = [...dump.matchAll(/COMDAT group section \[\s*(\d+)\].*contains (\d+) sections/g)]
      .map(match => ({ sectionIndex: Number(match[1]), count: Number(match[2]) }));
    assert.deepEqual(elf.sectionGroups.map(group => ({ sectionIndex: group.sectionIndex,
      count: group.members.length })), expected);
    assert.deepEqual(elf.sectionGroups.flatMap(group => group.issues), []);
    for (const group of elf.sectionGroups) {
      const section = elf.sections.find(item => item.index === group.sectionIndex)!;
      const name = elf.symbolTables?.find(table => table.sectionIndex === section.link)
        ?.entries[section.info]?.name;
      assert.ok(name && dump.includes(`[${name}]`));
    }
  } finally {
    execFileSync("wsl", ["--exec", "rm", "--", temporary]);
  }
});
