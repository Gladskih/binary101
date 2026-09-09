import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { probeWslReadelf } from "./elf-wsl-readelf-fixtures.js";

// System executables plus libc exercise requirements, definitions and hidden versions.
const paths = ["/usr/bin/ls", "/usr/bin/bash", "/lib/x86_64-linux-gnu/libc.so.6"];

for (const path of paths) {
  void test(`ELF symbol versions match readelf: ${path}`, async context => {
    const probe = probeWslReadelf();
    if (!probe.available) return context.skip(probe.reason);
    const bytes = execFileSync("wsl", ["--exec", "cat", path], { maxBuffer: 32 * 1024 * 1024 });
    const dump = execFileSync("wsl", ["--exec", "readelf", "-VW", path], { encoding: "utf8" });
    const elf = await parseElf(new File([bytes], path));
    assert.ok(elf?.symbolVersions);
    assert.deepEqual(elf.symbolVersions.issues, []);
    assert.equal(elf.symbolVersions.symbols.length,
      Number(/Version symbols section .* contains (\d+) entries/.exec(dump)?.[1]));
    const required = [...dump.matchAll(/Name: (\S+)\s+Flags: \S+\s+Version: (\d+)/g)]
      .map(match => ({ name: match[1], index: Number(match[2]) }));
    assert.deepEqual(elf.symbolVersions.requirements.flatMap(item => item.versions)
      .map(item => ({ name: item.name, index: item.index })), required);
    const defined = [...dump.matchAll(/Index: (\d+)\s+Cnt: \d+\s+Name: (\S+)/g)]
      .map(match => ({ index: Number(match[1]), name: match[2] }));
    assert.deepEqual(elf.symbolVersions.definitions
      .map(item => ({ index: item.index, name: item.names[0] })), defined);
    // Remove section headers in a copy: loader metadata must produce the same result.
    const sectionless = new Uint8Array(bytes);
    const view = new DataView(sectionless.buffer);
    view.setBigUint64(40, 0n, true); // ELF64 e_shoff.
    view.setUint16(60, 0, true); // e_shnum.
    view.setUint16(62, 0, true); // e_shstrndx.
    const loaded = await parseElf(new File([sectionless], path));
    assert.deepEqual(loaded?.symbolVersions, elf.symbolVersions);
  });
}
