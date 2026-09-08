import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmdirSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { probeWslReadelf } from "./elf-wsl-readelf-fixtures.js";
import type { ElfRelocationInfo } from "../../analyzers/elf/relocation-types.js";

const buildRelocationSamples = (directory: string): void => {
  const wslDirectory = execFileSync("wsl.exe", ["--exec", "wslpath", "-a", directory],
    { encoding: "utf8" }).trim();
  execFileSync("wsl.exe", ["--exec", "cc", "-g", "-fPIC", "-x", "c", "-c", "-",
    "-o", `${wslDirectory}/sample.o`], {
    input: "#include <stdio.h>\nint value = 7; int *pointer = &value;\n" +
      "int example(void) { puts(\"relocations\"); return *pointer; }\n"
  });
  execFileSync("wsl.exe", ["--exec", "cc", "-shared", "-Wl,-z,pack-relative-relocs",
    `${wslDirectory}/sample.o`, "-o", `${wslDirectory}/sample.so`]);
};

const readelfRelocations = (path: string) => {
  const wslPath = execFileSync("wsl.exe", ["--exec", "wslpath", "-a", path],
    { encoding: "utf8" }).trim();
  const output = execFileSync("wsl.exe", ["--exec", "env", "LC_ALL=C", "readelf", "-rW", wslPath],
    { encoding: "utf8" });
  return {
    symbolic: [...output.matchAll(/^([0-9a-f]{16})\s+([0-9a-f]{16})\s+R_\S+/gm)]
      .map(match => ({ offset: BigInt(`0x${match[1]}`), info: BigInt(`0x${match[2]}`) })),
    // GNU readelf's expanded RELR rows show encoded word then relocated address.
    relative: [...output.matchAll(/^\d{4}:\s+[0-9a-f]{16}\s+([0-9a-f]{16})/gm)]
      .map(match => BigInt(`0x${match[1]}`))
  };
};

const compareSample = async (path: string): Promise<ElfRelocationInfo> => {
  const expected = readelfRelocations(path);
  const result = await parseElf(new File([readFileSync(path)], "sample.elf"));
  assert.ok(result?.relocations);
  assert.ok(expected.symbolic.length > 0);
  assert.deepEqual(result.relocations.entries.filter(entry => entry.type != null).map(entry => ({
    offset: entry.offset, info: BigInt(entry.symbolIndex!) << 32n | BigInt(entry.type!)
  })), expected.symbolic);
  assert.deepEqual(result.relocations.entries.filter(entry => entry.type == null)
    .map(entry => entry.offset), expected.relative);
  assert.deepEqual(result.relocations.issues, []);
  return result.relocations;
};

const checkSectionlessSample = async (path: string, expected: ElfRelocationInfo): Promise<void> => {
  const bytes = readFileSync(path);
  // gABI Elf64_Ehdr: remove e_shoff, e_shnum and e_shstrndx from the copy.
  bytes.writeBigUInt64LE(0n, 40);
  bytes.writeUInt16LE(0, 60);
  bytes.writeUInt16LE(0, 62);
  const result = await parseElf(new File([bytes], "sectionless.so"));
  assert.ok(result?.relocations);
  assert.deepEqual(result.relocations.issues, []);
  assert.deepEqual(result.relocations.entries.map(entry =>
    `${entry.offset}:${entry.type}:${entry.symbolIndex}`).sort(),
  expected.entries.map(entry => `${entry.offset}:${entry.type}:${entry.symbolIndex}`).sort());
  assert.equal(result.relocations.entries.find(entry => entry.type === 7)?.symbol?.name, "puts");
  assert.ok(result.relocations.tables.some(table => table.encoding === "RELR"));
};

const removeSamples = (directory: string): void => {
  for (const name of ["sample.o", "sample.so"]) {
    const path = join(directory, name);
    if (existsSync(path)) unlinkSync(path);
  }
  rmdirSync(directory);
};

void test("ELF relocations match GNU readelf for objects, RELR and sectionless PLT", async context => {
  const probe = probeWslReadelf();
  if (!probe.available) {
    context.skip(probe.reason);
    return;
  }
  const directory = mkdtempSync(join(tmpdir(), "binary101-elf-relocations-"));
  try {
    buildRelocationSamples(directory);
    await compareSample(join(directory, "sample.o"));
    const shared = await compareSample(join(directory, "sample.so"));
    await checkSectionlessSample(join(directory, "sample.so"), shared);
  } finally {
    removeSamples(directory);
  }
});
