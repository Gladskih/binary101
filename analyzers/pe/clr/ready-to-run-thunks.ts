import type { FileRangeReader } from "../../file-range-reader.js";
import type { RvaToOffset } from "../types.js";
import type { PeClrReadyToRunSection, PeClrReadyToRunThunk } from "./ready-to-run-types.js";
import { readMappedRvaPrefix } from "../rva-byte-reader.js";
import { isRvaRange, mappedRvaSize } from "../rva-mapping.js";
import { readX86ReadyToRunThunk } from "./ready-to-run-thunk-x86.js";
import { readArm64ReadyToRunThunk } from "./ready-to-run-thunk-arm64.js";
import { readArmReadyToRunThunk } from "./ready-to-run-thunk-arm.js";

class ThunkWindow {
  #start = -1;
  #view: DataView = new DataView(new ArrayBuffer(0));
  constructor(readonly reader: FileRangeReader, readonly mapper: RvaToOffset) {}

  async read(rva: number, remaining: number): Promise<DataView> {
    // The supported compiler templates occupy at most 40 bytes (ARM64 including its literals).
    // 64 KiB is an I/O buffer size; every thunk in the declared range is visited.
    const needed = Math.min(40, remaining);
    if (rva < this.#start || rva + needed > this.#start + this.#view.byteLength) {
      this.#view = await readMappedRvaPrefix(this.reader, rva, Math.min(64 * 1024, remaining), this.mapper);
      this.#start = rva;
    }
    const offset = rva - this.#start;
    return new DataView(this.#view.buffer, this.#view.byteOffset + offset,
      Math.min(needed, this.#view.byteLength - offset));
  }
}

const paddingSize = (view: DataView, machine: number): number => {
  // SectionBuilder emits INT3 on x86/x64 and BRK #0xf000 on ARM64 as code alignment padding.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.ReadyToRun/ObjectWriter/SectionBuilder.cs
  if (machine === 0xaa64) return view.byteLength >= 4 && view.getUint32(0, true) === 0xd43e0000 ? 4 : 0;
  if (machine === 0x1c4) return view.byteLength >= 2 &&
    [0xdefe, 0xde01].includes(view.getUint16(0, true)) ? 2 : 0;
  return view.byteLength && view.getUint8(0) === 0xcc ? 1 : 0;
};

const validateCells = (thunk: PeClrReadyToRunThunk, reader: FileRangeReader,
  mapper: RvaToOffset, machine: number, warnings: Set<string>): void => {
  for (const rva of [thunk.helperCellRva, thunk.moduleCellRva]) {
    if (rva === undefined) continue;
    const width = [0x14c, 0x1c4].includes(machine) ? 4 : 8;
    if (rva === null || mappedRvaSize(mapper, rva, width, reader.size) !== width) {
      warnings.add("thunk data cell is invalid, truncated or unmapped");
    }
  }
};

const isSupportedRange = (section: PeClrReadyToRunSection, machine: number, issues: string[]): boolean => {
  if (section.size === 0) return false;
  if (![0x14c, 0x8664, 0xaa64, 0x1c4].includes(machine)) {
    issues.push("ReadyToRun thunks: compiler templates are unknown for this machine.");
    return false;
  }
  if (!isRvaRange(section.rva, section.size)) {
    issues.push("ReadyToRun thunks: invalid RVA range.");
    return false;
  }
  return true;
};

export const decodeReadyToRunThunkSection = async (
  reader: FileRangeReader, mapper: RvaToOffset, section: PeClrReadyToRunSection,
  machine: number, imageBase: bigint, issues: string[]
): Promise<PeClrReadyToRunThunk[]> => {
  const thunks: PeClrReadyToRunThunk[] = [];
  if (!isSupportedRange(section, machine, issues)) return thunks;
  const warnings = new Set<string>();
  const window = new ThunkWindow(reader, mapper);
  try {
    for (let offset = 0; offset < section.size;) {
      const rva = section.rva + offset;
      const view = await window.read(rva, section.size - offset);
      const padding = paddingSize(view, machine);
      if (padding) { offset += padding; continue; }
      const thunk = readThunk(view, rva, machine, imageBase);
      if (!thunk) { warnings.add(`unrecognized or truncated thunk at 0x${rva.toString(16)}`); break; }
      thunks.push(thunk);
      validateCells(thunk, reader, mapper, machine, warnings);
      offset += thunk.size;
    }
  } catch (error) { warnings.add(error instanceof Error ? error.message : "thunk range read failed"); }
  issues.push(...[...warnings].map(message => `ReadyToRun thunks: ${message}.`));
  return thunks;
};

const readThunk = (view: DataView, rva: number, machine: number, imageBase: bigint):
PeClrReadyToRunThunk | null => {
  if (machine === 0xaa64) return readArm64ReadyToRunThunk(view, rva, imageBase);
  if (machine === 0x1c4) return readArmReadyToRunThunk(view, rva, imageBase);
  return readX86ReadyToRunThunk(view, rva, machine, imageBase);
};
