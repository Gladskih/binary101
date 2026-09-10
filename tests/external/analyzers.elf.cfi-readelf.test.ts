import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { evaluateElfCfi } from "../../analyzers/elf/cfi-state.js";
import type { ElfUnwindFde } from "../../analyzers/elf/unwind-types.js";
import { probeWslReadelf } from "./elf-wsl-readelf-fixtures.js";

const frameBlocks = (dump: string): { offset: number; lines: string[] }[] => {
  const blocks: { offset: number; lines: string[] }[] = [];
  let current: { offset: number; lines: string[] } | null = null;
  for (const line of dump.split("\n")) {
    const header = line.match(/^([0-9a-f]+)[ \t]+.* FDE cie=/);
    if (header) {
      current = { offset: Number.parseInt(header[1]!, 16), lines: [] };
      blocks.push(current);
    } else if (!line.trim()) current = null;
    else current?.lines.push(line);
  }
  return blocks;
};

void test("computed CFA rows match readelf frames-interp on WSL ls", async context => {
  const probe = probeWslReadelf();
  if (!probe.available) return context.skip(probe.reason);
  const path = "/usr/bin/ls";
  const bytes = execFileSync("wsl", ["--exec", "cat", path], { maxBuffer: 64 * 1024 * 1024 });
  const dump = execFileSync("wsl", ["--exec", "readelf", "--debug-dump=frames-interp", "-W", path],
    { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  const elf = await parseElf(new File([bytes], path));
  const expected = frameBlocks(dump);
  assert.ok(expected.length > 0);
  const section = elf?.unwind?.[0];
  assert.ok(section);
  let compared = 0;
  for (const block of expected) {
    const fde: ElfUnwindFde | undefined = section.fdes.find(item => item.offset === block.offset);
    assert.ok(fde);
    const cie = section.cies.find(item => item.offset === fde.cieOffset);
    assert.ok(cie);
    const evaluation = evaluateElfCfi(cie, fde);
    assert.deepEqual(evaluation.issues, [], `FDE ${fde.offset}`);
    for (const match of block.lines.join("\n").matchAll(/^([0-9a-f]+)\s+(rsp|rbp)\+(-?\d+)\s/gm)) {
      const row = evaluation.rows.find(item => item.location === BigInt(`0x${match[1]}`));
      assert.ok(row, `FDE ${fde.offset} PC ${match[1]}`);
      assert.deepEqual(row.cfa, { register: match[2] === "rsp" ? 7n : 6n, offset: BigInt(match[3]!) });
      compared += 1;
    }
  }
  assert.ok(compared > 100, `${compared} CFA rows compared`);
});
