import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmdirSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { elfRelocationTypeName } from "../../analyzers/elf/relocation-names.js";

const readobj = process.env["BINARY101_LLVM_READOBJ"] ?? "llvm-readobj-21";
const linker = process.env["BINARY101_LLD"] ?? "ld.lld-21";
const run = (command: string, arguments_: string[], input?: string): string =>
  execFileSync("wsl.exe", ["--exec", command, ...arguments_],
    { encoding: "utf8", ...(input == null ? {} : { input }), stdio: ["pipe", "pipe", "pipe"] });
const source = "extern int external; static int local = 7; int *ptr = &local; " +
  "int example(void) { return external + *ptr; }";

type OracleRelocation = { Relocation: { Offset: string; Type: { Name: string; Value: number };
  Symbol: { Name: string; Value: number }; Addend?: string } };

const compareObject = async (path: string, linuxPath: string): Promise<void> => {
  // Keep 64-bit JSON integers exact before JSON.parse rounds them to JS numbers.
  const oracle = JSON.parse(run(readobj, ["--elf-output-style=JSON", "--relocations", "--expand-relocs", linuxPath])
    .replace(/"(Offset|Addend)":(\d+)/g, '"$1":"$2"')) as
    Array<{ Relocations: Array<{ SectionIndex: number; Relocs: OracleRelocation[] }> }>;
  const parsed = await parseElf(new File([readFileSync(path)], "compiler-produced.elf"));
  assert.ok(parsed?.relocations);
  const expected = oracle[0]!.Relocations.flatMap(section => section.Relocs.map(({ Relocation: record }) => ({
    section: section.SectionIndex, offset: BigInt(record.Offset), type: record.Type.Value,
    symbol: record.Symbol.Value, addend: record.Addend == null ? null :
      BigInt.asIntN(parsed.is64 ? 64 : 32, BigInt(record.Addend))
  })));
  assert.ok(expected.length > 0);
  assert.deepEqual(parsed.relocations.entries.map(entry => ({
    section: parsed.relocations!.tables[entry.tableIndex]!.sectionIndex, offset: entry.offset,
    type: entry.type, symbol: entry.symbolIndex, addend: entry.addend
  })), expected);
  assert.deepEqual(parsed.relocations.issues, []);
  for (const table of oracle[0]!.Relocations) {
    for (const { Relocation: record } of table.Relocs) {
      // LLVM formats all three N64 operations, including two trailing NONEs.
      const label: string = elfRelocationTypeName(parsed.header.machine, record.Type.Value).replaceAll(" / ", "/");
      assert.equal(label.replace(/(\/R_MIPS_NONE)+$/, ""), record.Type.Name.replace(/(\/R_MIPS_NONE)+$/, ""));
    }
  }
};

const comparePacked = async (path: string, linuxPath: string): Promise<void> => {
  const oracle = run(readobj, ["--relocations", "--expand-relocs", linuxPath]);
  const parsed = await parseElf(new File([readFileSync(path)], "linked.so"));
  assert.ok(parsed?.relocations);
  const expected = [...oracle.matchAll(/Offset: (0x[0-9A-Fa-f]+)[\s\S]*?Type: (R_\S+) \((\d+)\)[\s\S]*?Symbol: [^\n]* \((\d+)\)[\s\S]*?Addend: (0x[0-9A-Fa-f]+)/g)]
    .map(match => `${BigInt(match[1]!)}:${match[3]}:${match[4]}:${BigInt.asIntN(64, BigInt(match[5]!))}`).sort();
  assert.ok(expected.length > 0, oracle);
  assert.deepEqual(parsed.relocations.entries.map(entry =>
    `${entry.offset}:${entry.type}:${entry.symbolIndex}:${entry.addend}`).sort(), expected);
  assert.deepEqual(parsed.relocations.issues, []);
  const bytes = readFileSync(path);
  bytes.writeBigUInt64LE(0n, 40); // gABI e_shoff/shnum/shstrndx: sectionless copy.
  bytes.writeUInt16LE(0, 60);
  bytes.writeUInt16LE(0, 62);
  const sectionless = await parseElf(new File([bytes], "sectionless.so"));
  assert.ok(sectionless?.relocations);
  assert.deepEqual(sectionless.relocations.entries.map(entry =>
    `${entry.offset}:${entry.type}:${entry.symbolIndex}:${entry.addend}`).sort(), expected);
  assert.deepEqual(sectionless.relocations.issues, []);
};

void test("compiler-produced ELF relocations match unchanged LLVM across architectures and encodings", async context => {
  try { run(readobj, ["--version"]); run(linker, ["--version"]); }
  catch { context.skip("WSL LLVM readobj/lld unavailable; set BINARY101_LLVM_READOBJ and BINARY101_LLD."); return; }
  const directory = mkdtempSync(join(tmpdir(), "binary101-elf-codecs-"));
  const linuxDirectory = run("wslpath", ["-a", directory]).trim();
  try {
    for (const target of ["x86_64-linux-gnu", "i386-linux-gnu", "aarch64-linux-gnu", "aarch64_be-linux-gnu",
      "arm-linux-gnueabi", "armeb-linux-gnueabi", "mips64el-linux-gnuabi64", "mips64-linux-gnuabi64",
      "riscv64-linux-gnu", "powerpc-linux-gnu", "powerpc64-linux-gnu", "s390x-linux-gnu", "sparcv9-linux-gnu"]) {
      const name = `${target}.o`;
      run("clang-21", [`--target=${target}`, "-g", "-fPIC", "-x", "c", "-c", "-", "-o", `${linuxDirectory}/${name}`], source);
      await compareObject(join(directory, name), `${linuxDirectory}/${name}`);
    }
    for (const codec of ["zlib", "zstd"]) {
      run(readobj.replace("readobj", "objcopy"), [
        `--compress-sections=.rela.*=${codec}`, `${linuxDirectory}/x86_64-linux-gnu.o`,
        `${linuxDirectory}/compressed-${codec}.o`]);
      await compareObject(join(directory, `compressed-${codec}.o`), `${linuxDirectory}/x86_64-linux-gnu.o`);
    }
    run("clang-21", ["-g", "-fPIC", "-Wa,--crel,--allow-experimental-crel", "-x", "c", "-c", "-", "-o", `${linuxDirectory}/crel.o`], source);
    await compareObject(join(directory, "crel.o"), `${linuxDirectory}/crel.o`);
    run("clang-21", ["-fPIC", "-x", "c", "-c", "-", "-o", `${linuxDirectory}/sample.o`], source);
    run(linker, ["-shared", "--pack-dyn-relocs=android", `${linuxDirectory}/sample.o`, "-o", `${linuxDirectory}/android.so`]);
    await comparePacked(join(directory, "android.so"), `${linuxDirectory}/android.so`);
  } finally {
    for (const name of readdirSync(directory)) unlinkSync(join(directory, name));
    rmdirSync(directory);
  }
});
