import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmdirSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { analyzeElfInstructionSets } from "../../analyzers/elf/disassembly.js";
import { buildElfImportLinkageSamples } from "../helpers/elf-import-linkage-native.js";
import { probeWslReadelf } from "./elf-wsl-readelf-fixtures.js";

const compareLinkage = async (path: string): Promise<void> => {
  const file = new File([readFileSync(path)], basename(path));
  const elf = await parseElf(file);
  assert.ok(elf?.importLinkage);
  const target = execFileSync("wsl.exe", ["--exec", "wslpath", "-a", path],
    { encoding: "utf8" }).trim();
  const dump = execFileSync("wsl.exe", ["--exec", "readelf", "-rW", target], { encoding: "utf8" });
  const expected = [...dump.matchAll(/^([0-9a-f]+)\s+[0-9a-f]+\s+R_X86_64_(?:JUMP_SLOT|GLOB_DAT)/gm)]
    .map(match => BigInt(`0x${match[1]}`).toString()).sort();
  assert.deepEqual(elf.importLinkage.links.filter(link =>
    link.kind === "PLT slot" || link.kind === "GOT slot")
    .map(link => elf.relocations!.entries[link.relocationIndex]!.offset.toString()).sort(), expected);
  assert.deepEqual(elf.importLinkage.issues, []);
  assert.ok(elf.importLinkage.links.every(link => link.issues.length === 0));
  const puts = elf.importLinkage.links.find(link =>
    elf.relocations!.entries[link.relocationIndex]!.symbol?.name === "puts");
  assert.ok(puts);
  assert.equal(puts.kind, path.endsWith("no-plt.elf") ? "GOT slot" : "PLT slot");
  assert.equal(elf.importLinkage.binding, /(?:now|no-plt)\.elf$/.test(path)
    ? "Immediate binding requested" : "Lazy binding permitted");
  const report = await analyzeElfInstructionSets(file, {
    machine: elf.header.machine, fileType: elf.header.type, is64Bit: elf.is64,
    littleEndian: elf.littleEndian, entrypointVaddr: elf.header.entry,
    programHeaders: elf.programHeaders, sections: elf.sections,
    ...(elf.dynSymbols ? { dynSymbols: elf.dynSymbols } : {}),
    ...(elf.symbolTables ? { symbolTables: elf.symbolTables } : {}),
    ...(elf.relocations ? { relocations: elf.relocations } : {}), importLinkage: elf.importLinkage
  });
  const evidence = report.importCode?.find(entry =>
    entry.slotAddress === elf.relocations!.entries[puts.relocationIndex]!.offset);
  assert.ok(evidence, `${basename(path)}: puts code evidence`);
  assert.ok(evidence.references.some(reference => reference.kind ===
    (puts.kind === "GOT slot" ? "Indirect call" : "Call to stub")));
  const sectionless = readFileSync(path);
  // gABI Elf64_Ehdr: remove section table from a copy; dynamic metadata remains available.
  sectionless.writeBigUInt64LE(0n, 40);
  sectionless.writeUInt16LE(0, 60);
  sectionless.writeUInt16LE(0, 62);
  const stripped = await parseElf(new File([sectionless], "sectionless.elf"));
  assert.deepEqual(stripped?.importLinkage?.links.map(link =>
    stripped.relocations!.entries[link.relocationIndex]!.offset.toString()).sort(),
  elf.importLinkage.links.map(link => elf.relocations!.entries[link.relocationIndex]!.offset.toString()).sort());
};

void test("ELF linkage matches readelf for lazy, NOW, fno-plt, IBT and sectionless files", async context => {
  const probe = probeWslReadelf();
  if (!probe.available) { context.skip(probe.reason); return; }
  const directory = mkdtempSync(join(tmpdir(), "binary101-elf-linkage-"));
  const paths = buildElfImportLinkageSamples(directory);
  try {
    for (const path of paths) await compareLinkage(path);
  } finally {
    for (const path of paths) unlinkSync(path);
    rmdirSync(directory);
  }
});
