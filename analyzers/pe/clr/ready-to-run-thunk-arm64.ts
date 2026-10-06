import type { PeClrReadyToRunThunk } from "./ready-to-run-types.js";
import { isRvaRange } from "../rva-mapping.js";

// ImportThunk emits MOVZ/LDR prefixes followed by ARM64Emitter.EmitJMP's LDR/LDR/BR
// and an inline DIR64 relocation for the helper cell. Non-eager stubs append the module literal.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.ReadyToRun/Compiler/DependencyAnalysis/ReadyToRun/Target_ARM64/ImportThunk.cs
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Compiler/DependencyAnalysis/Target_ARM64/ARM64Emitter.cs
const matchWords = (view: DataView, offset: number, words: number[]): boolean =>
  view.byteLength >= offset + words.length * 4 &&
  words.every((word, index) => view.getUint32(offset + index * 4, true) === word);

const prefixSize = (view: DataView): number | null => {
  if (view.byteLength < 20) return null;
  if (view.getUint32(0, true) === 0x5800006c) return 0;
  if (view.byteLength >= 36 && matchWords(view, 0, [0x580000e1, 0xf9400021])) return 8;
  if (view.byteLength >= 40 && ((view.getUint32(0, true) & 0xffe0001f) >>> 0) === 0xd2800009 &&
      matchWords(view, 4, [0x580000ea, 0xf940014a])) return 12;
  return null;
};

const literalRva = (view: DataView, offset: number, imageBase: bigint): number | null => {
  const address = view.getBigUint64(offset, true) - imageBase;
  return address >= 0n && address < 0x100000000n ? Number(address) : null;
};

export const readArm64ReadyToRunThunk = (
  view: DataView, rva: number, imageBase: bigint
): PeClrReadyToRunThunk | null => {
  if (rva % 4) return null;
  const prefix = prefixSize(view);
  if (prefix === null) return null;
  const size = prefix + 20 + (prefix ? 8 : 0);
  if (!isRvaRange(rva, size)) return null;
  if (!matchWords(view, prefix, [0x5800006c, 0xf940018c, 0xd61f0180])) return null;
  const thunk: PeClrReadyToRunThunk = { rva, size,
    kind: thunkKind(prefix),
    helperCellRva: literalRva(view, prefix + 12, imageBase) };
  if (prefix) thunk.moduleCellRva = literalRva(view, prefix + 20, imageBase);
  if (prefix === 12) thunk.importSectionIndex = (view.getUint32(0, true) >>> 5) & 0xffff;
  return thunk;
};

const thunkKind = (prefix: number): PeClrReadyToRunThunk["kind"] =>
  prefix === 0 ? "eager" : prefix === 8 ? "lazy" : "delay-load family";
