import { execFile } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import type { PeWindowsParseResult } from "../../analyzers/pe/core/parse-result.js";
import {
  COFF_FILE_HEADER_BYTE_LENGTH, COFF_SECTION_HEADER_BYTE_LENGTH, COFF_SHORT_NAME_BYTE_LENGTH
} from "../../analyzers/coff/layout.js";

const run = promisify(execFile);

// Independent UI expectation: match the existing PE exports/RTTI table page size.
// This is presentation policy, not a D ABI limit.
export const D_TEST_PAGE_SIZE = 250;

export const hasWindowsDCompiler = async (): Promise<boolean> => {
  if (process.platform !== "win32") return false;
  try {
    await run("dmd", ["--version"]);
    return true;
  } catch {
    return false;
  }
};

const writeSample = (directory: string): Promise<void> => writeFile(join(directory, "sample.d"),
  `module sample;
import std.stdio;
class Animal { int number; }
class Dog : Animal { override string toString() { return "dog"; } }
static this() {}
static ~this() {}
shared static this() {}
shared static ~this() {}
unittest { assert(true); }
void main() {
    foreach (info; ModuleInfo)
        writeln(info.name, "|", info.flags & ~(MIctorstart | MIctordone), "|",
            info.importedModules.length, "|", info.localClasses.length);
}
`);

export const buildDRuntimeProgram = async (directory: string, flags: string[]) => {
  await writeSample(directory);
  const executable = join(directory, "sample.exe");
  await run("dmd", [...flags, "-unittest", `-of=${executable}`, "sample.d"], { cwd: directory });
  return { bytes: await readFile(executable),
    modules: (await run(executable, ["--DRT-testmode=run-main"], { cwd: directory }))
      .stdout.trim().split(/\r?\n/).map(line => line.split("|")) };
};

export const buildPagedDRuntimeProgram = async (directory: string) => {
  await writeSample(directory);
  // Generate more modules than one page, independent of the installed runtime's module count.
  const extraModules = Array.from({ length: D_TEST_PAGE_SIZE + 1 }, (_, index) => `dummy${index}.d`);
  await Promise.all(extraModules.map((name, index) => writeFile(join(directory, name),
    `module dummy${index}; shared static this() {}`)));
  await run("dmd", ["-m64", "-unittest", "-of=sample.exe", "sample.d", ...extraModules],
    { cwd: directory });
  return readFile(join(directory, "sample.exe"));
};

export const renameDRuntimePeSections = (bytes: Uint8Array, parsed: PeWindowsParseResult): void => {
  // Build a renamed input using existing PE layout definitions, not as a parsing oracle.
  // The four-byte PE signature precedes the COFF header (Microsoft PE file headers).
  const tableOffset = parsed.dos.e_lfanew + Uint32Array.BYTES_PER_ELEMENT +
    COFF_FILE_HEADER_BYTE_LENGTH + parsed.coff.SizeOfOptionalHeader;
  parsed.sections.forEach((_section, index) => {
    bytes.fill(0, tableOffset + index * COFF_SECTION_HEADER_BYTE_LENGTH,
      tableOffset + index * COFF_SECTION_HEADER_BYTE_LENGTH + COFF_SHORT_NAME_BYTE_LENGTH);
    bytes.set(new TextEncoder().encode(`.s${index}`),
      tableOffset + index * COFF_SECTION_HEADER_BYTE_LENGTH);
  });
};
