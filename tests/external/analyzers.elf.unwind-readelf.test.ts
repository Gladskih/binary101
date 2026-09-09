import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { probeWslReadelf } from "./elf-wsl-readelf-fixtures.js";

for (const path of ["/usr/bin/ls", "/usr/bin/bash", "/lib/x86_64-linux-gnu/libc.so.6"]) {
  void test(`unwind CIE/FDE records match readelf: ${path}`, async context => {
    const probe = probeWslReadelf();
    if (!probe.available) return context.skip(probe.reason);
    const bytes = execFileSync("wsl", ["--exec", "cat", path], { maxBuffer: 32 * 1024 * 1024 });
    const dump = execFileSync("wsl", ["--exec", "readelf", "--debug-dump=frames", "-W", path],
      { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
    const elf = await parseElf(new File([bytes], path));
    assert.ok(elf?.unwind?.length);
    const expected = [...dump.matchAll(/^([0-9a-f]+)\s+[0-9a-f]+\s+[0-9a-f]+\s+FDE cie=([0-9a-f]+) pc=([0-9a-f]+)\.\.([0-9a-f]+)/gm)]
      .map(match => ({ offset: Number.parseInt(match[1]!, 16), cieOffset: Number.parseInt(match[2]!, 16),
        start: BigInt(`0x${match[3]}`), range: BigInt(`0x${match[4]}`) - BigInt(`0x${match[3]}`) }));
    assert.ok(expected.length > 0);
    assert.deepEqual(elf.unwind.flatMap(section => section.fdes).map(fde => ({ offset: fde.offset,
      cieOffset: fde.cieOffset, start: fde.start?.address, range: fde.range })), expected);
    assert.equal(elf.unwind.flatMap(section => section.cies).length,
      [...dump.matchAll(/^[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+\s+CIE/gm)].length);
    assert.deepEqual(elf.unwind.flatMap(section => section.issues), []);
  });
}
