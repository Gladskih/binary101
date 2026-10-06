import type { PeClrReadyToRunThunk } from "./ready-to-run-types.js";
import { isRvaRange } from "../rva-mapping.js";

interface ThunkPattern {
  prefix: readonly number[];
  kind: PeClrReadyToRunThunk["kind"];
  jump: number;
  module?: number;
  index?: number;
}

// Exact instruction sequences emitted by ImportThunk, including the PUSH imm8 table index.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.ReadyToRun/Compiler/DependencyAnalysis/ReadyToRun/Target_X64/ImportThunk.cs
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.ReadyToRun/Compiler/DependencyAnalysis/ReadyToRun/Target_X86/ImportThunk.cs
const commonPatterns: readonly ThunkPattern[] = [
  { prefix: [0xff, 0x25], kind: "eager", jump: 0 },
  { prefix: [0x33, 0xc0, 0x6a], kind: "delay-load", jump: 10, module: 4, index: 3 }
];
const x64Patterns: readonly ThunkPattern[] = [...commonPatterns,
  { prefix: [0x6a], kind: "tailcall", jump: 8, module: 2, index: 1 },
  { prefix: [0x49, 0x8b, 0xc3, 0x6a], kind: "virtual-dispatch", jump: 11, module: 5, index: 4 },
  { prefix: [0x48, 0x8b, 0x15], kind: "lazy", jump: 7, module: 0 },
  { prefix: [0x48, 0x8b, 0x35], kind: "lazy", jump: 7, module: 0 }
];
const x86Patterns: readonly ThunkPattern[] = [...commonPatterns,
  { prefix: [0x8b, 0x15], kind: "lazy", jump: 6, module: 0 }
];

const matches = (view: DataView, pattern: ThunkPattern): boolean => {
  if (view.byteLength < pattern.jump + 6) return false;
  if (!pattern.prefix.every((byte, index) => view.getUint8(index) === byte)) return false;
  if (view.getUint16(pattern.jump, true) !== 0x25ff) return false;
  return pattern.module === undefined || pattern.kind === "lazy" ||
    view.getUint16(pattern.module, true) === 0x35ff;
};

const cellRva = (view: DataView, operand: number, nextRva: number,
  machine: number, imageBase: bigint): number | null => {
  const address = machine === 0x8664 ? BigInt(nextRva + view.getInt32(operand, true))
    : BigInt(view.getUint32(operand, true)) - imageBase;
  return address >= 0n && address < 0x100000000n ? Number(address) : null;
};

const readModuleCell = (view: DataView, pattern: ThunkPattern, rva: number,
  machine: number, imageBase: bigint): number | null => {
  const operand = pattern.module! + (pattern.kind === "lazy" && machine === 0x8664 ? 3 : 2);
  return cellRva(view, operand, rva + operand + 4, machine, imageBase);
};

export const readX86ReadyToRunThunk = (
  view: DataView, rva: number, machine: number, imageBase: bigint
): PeClrReadyToRunThunk | null => {
  if (machine !== 0x8664 && machine !== 0x14c) return null;
  const pattern = (machine === 0x8664 ? x64Patterns : x86Patterns).find(item => matches(view, item));
  if (!pattern || !isRvaRange(rva, pattern.jump + 6)) return null;
  const thunk: PeClrReadyToRunThunk = { rva, size: pattern.jump + 6, kind: pattern.kind,
    helperCellRva: cellRva(view, pattern.jump + 2, rva + pattern.jump + 6, machine, imageBase) };
  if (pattern.module !== undefined) {
    thunk.moduleCellRva = readModuleCell(view, pattern, rva, machine, imageBase);
  }
  if (pattern.index !== undefined) thunk.importSectionIndex = view.getInt8(pattern.index);
  return thunk;
};
