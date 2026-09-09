import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { describeElfGnuProperty } from "../../renderers/elf/gnu-properties.js";
import { probeWslReadelf } from "./elf-wsl-readelf-fixtures.js";

void test("GNU properties match readelf on real WSL libc", async context => {
  const probe = probeWslReadelf();
  if (!probe.available) return context.skip(probe.reason);
  const path = "/lib/x86_64-linux-gnu/libc.so.6";
  const bytes = execFileSync("wsl", ["--exec", "cat", path], { maxBuffer: 32 * 1024 * 1024 });
  const dump = execFileSync("wsl", ["--exec", "readelf", "-nW", path], { encoding: "utf8" });
  const elf = await parseElf(new File([bytes], path));
  assert.ok(elf?.notes);
  const properties = elf.notes.entries.flatMap(note => note.properties ?? []);
  assert.ok(properties.length > 0);
  const descriptions = properties.map(property => describeElfGnuProperty(property, elf.header.machine));
  for (const expected of ["IBT", "SHSTK", "x86-64-baseline"]) {
    assert.equal(descriptions.some(text => text.includes(expected)), dump.includes(expected), expected);
  }
  assert.deepEqual(elf.notes.issues, []);
  const sectionless = new Uint8Array(bytes);
  const view = new DataView(sectionless.buffer);
  view.setBigUint64(40, 0n, true);
  view.setUint16(60, 0, true);
  view.setUint16(62, 0, true);
  const loaded = await parseElf(new File([sectionless], path));
  assert.deepEqual(loaded?.notes?.entries.flatMap(note => note.properties ?? []), properties);
});
