import type { PeClrReadyToRunThunk } from "./ready-to-run-types.js";
import { isRvaRange } from "../rva-mapping.js";

interface ArmThunkPattern {
  size: number;
  kind: PeClrReadyToRunThunk["kind"];
  helper: number;
  helperRegister: number;
  module?: number;
  moduleRegister?: number;
  cellEncoding: "pc-relative" | "absolute";
  words: readonly (readonly [offset: number, word: number, mask?: number])[];
}

// Thumb2 sequences emitted by ARMEmitter and ImportThunk; MOVW/MOVT relocations are PC-relative.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.ReadyToRun/Compiler/DependencyAnalysis/ReadyToRun/Target_ARM/ImportThunk.cs
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Compiler/DependencyAnalysis/Target_ARM/ARMEmitter.cs
const patterns: readonly ArmThunkPattern[] = [
  { size: 16, kind: "eager", helper: 0, helperRegister: 12, cellEncoding: "pc-relative",
    words: [[10, 0xf8dc], [12, 0xc000], [14, 0x4760]] },
  { size: 28, kind: "lazy", helper: 12, helperRegister: 12, module: 0, moduleRegister: 1,
    cellEncoding: "pc-relative",
    words: [[10, 0x6809], [22, 0xf8dc], [24, 0xc000], [26, 0x4760]] },
  { size: 40, kind: "delay-load family", helper: 26, helperRegister: 4, module: 10, moduleRegister: 4,
    cellEncoding: "pc-relative",
    words: [[0, 0xf84d], [2, 0x4d04], [4, 0x2400, 0xff00], [6, 0xf84d], [8, 0x4d04],
      [20, 0x6824], [22, 0xf84d], [24, 0x4d04], [36, 0x6824], [38, 0x4720]] },
  // Earlier emitters relocate the MOV pair to an absolute VA, without ADD PC.
  // https://github.com/dotnet/runtime/blob/v8.0.0/src/coreclr/tools/Common/Compiler/DependencyAnalysis/Target_ARM/ARMEmitter.cs
  { size: 14, kind: "eager", helper: 0, helperRegister: 12, cellEncoding: "absolute",
    words: [[8, 0xf8dc], [10, 0xc000], [12, 0x4760]] },
  { size: 24, kind: "lazy", helper: 10, helperRegister: 12, module: 0, moduleRegister: 1,
    cellEncoding: "absolute", words: [[8, 0x6809], [18, 0xf8dc], [20, 0xc000], [22, 0x4760]] },
  { size: 36, kind: "delay-load family", helper: 24, helperRegister: 4, module: 10, moduleRegister: 4,
    cellEncoding: "absolute", words: [[0, 0xf84d], [2, 0x4d04], [4, 0x2400, 0xff00], [6, 0xf84d], [8, 0x4d04],
      [18, 0x6824], [20, 0xf84d], [22, 0x4d04], [32, 0x6824], [34, 0x4720]] }
];

const matchMovePair = (view: DataView, offset: number, register: number): boolean =>
  [[0, 0xf240, 0xfbf0], [2, register << 8, 0x8f00],
    [4, 0xf2c0, 0xfbf0], [6, register << 8, 0x8f00]]
    .every(([position, word, mask]) => (view.getUint16(offset + position!, true) & mask!) === word);

const readImmediate = (view: DataView, offset: number): number =>
  ((view.getUint16(offset, true) & 0xf) << 12) |
  ((view.getUint16(offset, true) & 0x400) << 1) |
  ((view.getUint16(offset + 2, true) & 0x7000) >>> 4) | (view.getUint16(offset + 2, true) & 0xff);

const readCell = (view: DataView, offset: number, rva: number, register: number,
  encoding: ArmThunkPattern["cellEncoding"], imageBase: bigint): number | null | undefined => {
  if (!matchMovePair(view, offset, register)) return undefined;
  // RelocationHelper: targetRVA - (sourceRVA + 12); the MOVW/MOVT immediate is signed int32.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.ReadyToRun/ObjectWriter/RelocationHelper.cs
  const immediate = readImmediate(view, offset) | (readImmediate(view, offset + 4) << 16);
  if (encoding === "absolute") {
    const cell = BigInt(immediate >>> 0) - imageBase;
    return cell >= 0n && cell < 0x100000000n ? Number(cell) : null;
  }
  if (view.getUint16(offset + 8, true) !== (register <= 7 ? 0x4478 + register : 0x44f0 + register)) {
    return undefined;
  }
  return isRvaRange(rva + offset + 12 + immediate, 1) ? rva + offset + 12 + immediate : null;
};

export const readArmReadyToRunThunk = (
  view: DataView, rva: number, imageBase = 0n
): PeClrReadyToRunThunk | null => {
  if (rva % 2) return null;
  const pattern = patterns.find(item => view.byteLength >= item.size && item.words.every(
    ([offset, word, mask]) => (view.getUint16(offset, true) & (mask ?? 0xffff)) === word));
  if (!pattern || !isRvaRange(rva, pattern.size)) return null;
  const helper = readCell(view, pattern.helper, rva, pattern.helperRegister, pattern.cellEncoding, imageBase);
  if (helper === undefined) return null;
  const thunk: PeClrReadyToRunThunk = { rva, size: pattern.size, kind: pattern.kind, helperCellRva: helper };
  if (pattern.module !== undefined) {
    const module = readCell(view, pattern.module, rva, pattern.moduleRegister!, pattern.cellEncoding, imageBase);
    if (module === undefined) return null;
    thunk.moduleCellRva = module;
  }
  if (pattern.kind === "delay-load family") thunk.importSectionIndex = view.getUint16(4, true) & 0xff;
  return thunk;
};
