import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { probeWslReadelf } from "./elf-wsl-readelf-fixtures.js";

void test("all static symbols match readelf on real WSL object files", async context => {
  const probe = probeWslReadelf();
  if (!probe.available) return context.skip(probe.reason);
  const paths = execFileSync("wsl", ["--exec", "sh", "-c",
    "find /usr/lib/gcc -name '*.o' | head -12"], { encoding: "utf8" }).trim().split("\n");
  assert.ok(paths.length >= 3);
  for (const path of paths) {
    const bytes = execFileSync("wsl", ["--exec", "cat", path]);
    const dump = execFileSync("wsl", ["--exec", "readelf", "-sW", path], { encoding: "utf8" });
    const elf = await parseElf(new File([bytes], path));
    assert.ok(elf?.symbolTables?.length, path);
    const rows = [...dump.matchAll(/^ *\d+: +([0-9a-f]+) +(\d+) +\S+ +\S+ +\S+ +(\S+) *(.*)$/gm)]
      .map(match => ({ value: BigInt(`0x${match[1]}`), size: BigInt(match[2]!),
        sectionIndex: ({ UND: 0, ABS: 65521, COM: 65522 } as Record<string, number>)[match[3]!] ??
          Number(match[3]), name: match[4]!.trim() }));
    const symbols = elf.symbolTables.flatMap(table => table.entries);
    assert.equal(symbols.length, rows.length, path);
    // readelf synthesizes section names for STT_SECTION; raw st_name is often empty.
    assert.deepEqual(symbols.map(symbol => ({ value: symbol.value, size: symbol.size,
      sectionIndex: symbol.sectionIndex })), rows.map(({ value, size, sectionIndex }) =>
      ({ value, size, sectionIndex })), path);
    assert.deepEqual(symbols.filter(symbol => (symbol.info & 15) !== 3).map(symbol => symbol.name),
      rows.filter((_, index) => (symbols[index]!.info & 15) !== 3).map(row => row.name), path);
    assert.deepEqual(elf.symbolTables.flatMap(table => table.issues), [], path);
  }
});
