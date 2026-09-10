import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { probeWslReadelf } from "./elf-wsl-readelf-fixtures.js";

void test("GNU hash bucket histogram matches real WSL libc", async context => {
  const probe = probeWslReadelf();
  if (!probe.available) return context.skip(probe.reason);
  const path = "/lib/x86_64-linux-gnu/libc.so.6";
  const bytes = execFileSync("wsl", ["--exec", "cat", path], { maxBuffer: 32 * 1024 * 1024 });
  const dump = execFileSync("wsl", ["--exec", "readelf", "-IW", path], { encoding: "utf8" });
  const parsed = await parseElf(new File([bytes], path));
  const table = parsed?.hashTables?.find(item => item.kind === "gnu");
  assert.ok(table?.kind === "gnu");
  assert.deepEqual(table.issues, []);
  const expected = [...dump.slice(dump.indexOf("Histogram for `.gnu.hash'")).matchAll(/^\s*(\d+)\s+(\d+)\s+\(/gm)]
    .map(match => [Number(match[1]), Number(match[2])]);
  assert.ok(expected.length > 0);
  const histogram = new Map<number, number>();
  for (const bucket of table.buckets) {
    let length = 0;
    if (bucket) {
      let index = bucket - table.symbolOffset;
      do { length += 1; } while (!(table.chains[index++]! & 1));
    }
    histogram.set(length, (histogram.get(length) ?? 0) + 1);
  }
  assert.deepEqual(expected.map(([length]) => [length, histogram.get(length!) ?? 0]), expected);
});
