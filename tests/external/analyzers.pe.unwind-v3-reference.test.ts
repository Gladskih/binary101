import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { parseExceptionDirectory } from "../../analyzers/pe/exception/index.js";
import { decodeAmd64UnwindV3 } from "../../analyzers/pe/exception/amd64/unwind-v3.js";
import type { Amd64WindingOperation, Amd64UnwindV3 } from "../../analyzers/pe/exception/amd64/unwind-v3-types.js";
import { MockFile } from "../helpers/mock-file.js";

// Unchanged LLVM assembler fixtures, produced by unchanged llvm-mc 23.1.5
// (-triple x86_64-pc-win32 -mattr=+push2pop2,+egpr -filetype=obj), linked by lld-link.
// https://github.com/llvm/llvm-project/tree/llvmorg-23.1.3/llvm/test/MC/COFF
// Oracle: unchanged llvm-readobj 23.1.5 from authenticated apt.llvm.org packages.
// The generated DLLs are inspected statically and never executed.
const wslPath = (path: string): string => `/mnt/${path[0]!.toLowerCase()}${path.slice(2).replaceAll("\\", "/")}`;
const hex = (value: number): string => `0x${value.toString(16).toUpperCase()}`;
const registerName = (register: number): string => register < 8
  ? ["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI"][register]!
  : `R${register}`;

const formatOperation = (operation: Amd64WindingOperation): string => {
  if ("size" in operation) return `${operation.opcode} Size=${hex(operation.size)}`;
  if ("frameType" in operation) return `${operation.opcode} Type=${operation.frameType}`;
  if (operation.opcode === "PUSH2") {
    return `PUSH2 Reg1=${registerName(operation.register)}, Reg2=${registerName(operation.register2)}`;
  }
  if (operation.opcode === "PUSH") return `PUSH Reg=${registerName(operation.register)}`;
  if (operation.opcode === "PUSH_CONSECUTIVE_2") {
    return `PUSH_CONSECUTIVE_2 Reg=${registerName(operation.register)} (+${registerName(operation.register + 1)})`;
  }
  if (operation.opcode === "SET_FPREG") {
    return `SET_FPREG Reg=${registerName(operation.register)}, Offset=${hex(operation.displacement)}`;
  }
  assert.ok("displacement" in operation);
  return `${operation.opcode} Reg=${operation.opcode.startsWith("SAVE_XMM")
    ? `XMM${operation.register}` : registerName(operation.register)}, Disp=${hex(operation.displacement)}`;
};

const operationLines = (operations: Amd64WindingOperation[], offsets: number[]): string[] =>
  operations.map((operation, index) => `[${index}] IP +0x${offsets[index]!.toString(16).toUpperCase().padStart(4, "0")}: ` +
    formatOperation(operation));

const windingLines = (records: Amd64UnwindV3[]): string[] => records.flatMap(record => [
  ...operationLines(record.prologOperations, record.prologIpOffsets),
  ...record.epilogs.flatMap(epilog => epilog.kind === "full" ? operationLines(epilog.operations, epilog.ipOffsets) : [])
]);

const readImageRecords = async (file: MockFile) => {
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const directory = core.dataDirs.find(entry => entry.name === "EXCEPTION");
  assert.ok(directory);
  const offset = core.rvaToOff(directory.rva);
  assert.ok(offset != null);
  const view = new DataView(file.data.buffer);
  const records: Amd64UnwindV3[] = [];
  const issues: string[] = [];
  for (let position = offset; position < offset + directory.size; position += 12) {
    const xdata: number | null = core.rvaToOff(view.getUint32(position + 8, true));
    assert.ok(xdata != null);
    const record = decodeAmd64UnwindV3(new DataView(file.data.buffer,
      xdata, 4 + view.getUint8(xdata + 2) * 2), issues);
    assert.ok(record);
    records.push(record);
  }
  return { core, records, issues };
};

for (const name of ["seh-unwindv3", "seh-unwindv3-inheritance", "seh-unwindv3-large",
  "seh-unwindv3-nonmirror", "seh-unwindv3-pool-sharing"]) {
  void test(`V3 payloads and PE dispatch match unchanged LLVM: ${name}`, async () => {
    const path = resolve(`scan-results/unwind-v3/${name}.dll`);
    const file = new MockFile(await readFile(path));
    const { core, records, issues } = await readImageRecords(file);
    const parsed = await parseExceptionDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
    const root = wslPath(resolve("scan-results/llvm23-resolute/root"));
    const oracle = execFileSync("wsl.exe", ["env", `LD_LIBRARY_PATH=${root}/usr/lib/x86_64-linux-gnu`,
      `${root}/usr/lib/llvm-23/bin/llvm-readobj`, "--unwind", wslPath(path)], { encoding: "utf8" });

    assert.equal(records.length, [...oracle.matchAll(/Version: 3/g)].length);
    assert.equal(parsed?.unwindInfoV3?.blockCount, records.length);
    assert.equal(parsed?.invalidEntryCount, 0);
    assert.deepEqual(records.map(record => record.prologSize),
      [...oracle.matchAll(/SizeOfProlog: 0x([0-9A-F]+)/g)].map(match => Number.parseInt(match[1]!, 16)));
    assert.deepEqual(records.flatMap(record => record.epilogs.map(epilog => epilog.offset)),
      [...oracle.matchAll(/EpilogOffset: (-?0x[0-9A-F]+)/g)].map(match => Number.parseInt(match[1]!, 16)));
    assert.deepEqual(windingLines(records),
      [...oracle.matchAll(/^\s*(\[\d+\] IP \+0x[0-9A-F]+: .+)$/gm)].map(match => match[1]!.trim()));
    assert.deepEqual(issues, []);
    assert.deepEqual(parsed?.issues, []);
  });
}
