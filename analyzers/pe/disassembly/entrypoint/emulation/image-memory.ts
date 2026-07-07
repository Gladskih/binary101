"use strict";

import type { FileRangeReader } from "../../../../file-range-reader.js";
import type { AnalyzePeEntrypointDisassemblyOptions } from "../../types.js";
import { MAX_RVA, RVA_EXCLUSIVE_LIMIT } from "../metadata.js";
import type { IcedInstructionObject, IcedModule } from "../iced.js";
import {
  operandBits,
  resolveMemoryAddresses
} from "./operands.js";
import { resolveRegister } from "./registers.js";
import {
  collectKnownValues,
  known,
  readRegister,
  type EmulationState,
  type KnownValueBits
} from "./state.js";
import { readFlag } from "./flags.js";
import { isAnyMnemonic } from "./integer/common.js";
import { movsElementBytes } from "./movs-memory-copy.js";

const MOVS_MNEMONICS = ["Movsb", "Movsw", "Movsd", "Movsq"] as const;
// Keep speculative REP MOVS image reads bounded; larger copies remain unknown
// instead of turning one decoded instruction into an unbounded file scan.
const MAX_IMAGE_MEMORY_PRELOAD_CELLS = 256;

type PreloadedImageMemory = {
  touchedKeys: Set<string>;
};

type StringPointer = {
  registerName: string;
  bits: KnownValueBits;
};

const memorySizeBits = (
  iced: IcedModule,
  instruction: IcedInstructionObject
): KnownValueBits | null => {
  const name = iced.MemorySize?.[instruction.memorySize];
  if (name === "UInt8") return 8;
  if (name === "UInt16") return 16;
  if (name === "UInt32") return 32;
  if (name === "UInt64") return 64;
  return null;
};

const stringPointer = (
  iced: IcedModule,
  instruction: IcedInstructionObject,
  operand: number,
  suffix: "SI" | "DI"
): StringPointer | null => {
  const name = iced.OpKind[instruction.opKind(operand)];
  if (!name?.endsWith(suffix)) return null;
  if (name.endsWith(`E${suffix}`)) return { registerName: `E${suffix}`, bits: 32 };
  if (name.endsWith(`R${suffix}`)) return { registerName: `R${suffix}`, bits: 64 };
  return { registerName: suffix, bits: 16 };
};

const knownSingleValue = (
  iced: IcedModule,
  state: EmulationState,
  registerName: string
): bigint | null => {
  const values = collectKnownValues(
    readRegister(state, resolveRegister(iced, iced.Register?.[registerName] ?? 0))
  );
  return values.length === 1 ? values[0]?.value ?? null : null;
};

const repeatedCount = (
  iced: IcedModule,
  state: EmulationState,
  sourceBits: KnownValueBits,
  instruction: IcedInstructionObject
): bigint | null => {
  if (!instruction.hasRepPrefix && !instruction.hasRepePrefix && !instruction.hasRepnePrefix) {
    return 1n;
  }
  const registerName = sourceBits === 16 ? "CX" : sourceBits === 32 ? "ECX" : "RCX";
  return knownSingleValue(iced, state, registerName);
};

const imageRva = (
  opts: AnalyzePeEntrypointDisassemblyOptions,
  address: bigint
): number | null => {
  if (address < opts.imageBase) return null;
  const rva = address - opts.imageBase;
  if (rva > BigInt(MAX_RVA)) return null;
  const value = Number(rva);
  return Number.isSafeInteger(value) && value >= 0 ? value >>> 0 : null;
};

const sectionField = (value: number): number | null =>
  Number.isSafeInteger(value) && value >= 0 && value <= MAX_RVA ? value >>> 0 : null;

const rvaRangeEnd = (rva: number, size: number): number | null => {
  if (!Number.isSafeInteger(size) || size <= 0) return null;
  const end = rva + size;
  return end <= RVA_EXCLUSIVE_LIMIT ? end : null;
};

const isZeroFilledRvaRange = (
  opts: AnalyzePeEntrypointDisassemblyOptions,
  rva: number,
  size: number
): boolean => {
  const end = rvaRangeEnd(rva, size);
  if (end == null) return false;
  for (const section of opts.sections) {
    const start = sectionField(section.virtualAddress);
    const virtualSize = sectionField(section.virtualSize);
    const rawSize = sectionField(section.sizeOfRawData);
    if (start == null || virtualSize == null || rawSize == null || virtualSize <= rawSize) {
      continue;
    }
    // Microsoft PE format: if VirtualSize is greater than SizeOfRawData,
    // the loaded section tail is zero-filled rather than file-backed.
    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    const zeroStart = start + rawSize;
    const zeroEnd = Math.min(start + virtualSize, RVA_EXCLUSIVE_LIMIT);
    if (rva >= zeroStart && end <= zeroEnd) return true;
  }
  return false;
};

const readLittleEndian = (view: DataView): bigint => {
  let value = 0n;
  for (let index = 0; index < view.byteLength; index += 1) {
    value |= BigInt(view.getUint8(index)) << BigInt(index * 8);
  }
  return value;
};

const readImageValue = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  address: bigint,
  bits: KnownValueBits
): Promise<bigint | null> => {
  const rva = imageRva(opts, address);
  const offset = rva == null ? null : opts.rvaToOff(rva);
  const size = bits / 8;
  if (rva != null && offset == null && isZeroFilledRvaRange(opts, rva, size)) return 0n;
  if (offset == null || !Number.isSafeInteger(offset) || offset < 0) return null;
  if (offset > reader.size - size) return null;
  const view = await reader.read(offset, size);
  if (view.byteLength !== size) return null;
  return readLittleEndian(view);
};

const preloadCell = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  state: EmulationState,
  touchedKeys: Set<string>,
  address: bigint,
  bits: KnownValueBits
): Promise<void> => {
  const key = address.toString();
  touchedKeys.add(key);
  if (state.memory.has(key)) return;
  const value = await readImageValue(reader, opts, address, bits);
  if (value != null) state.memory.set(key, known(value, bits));
};

const preloadExplicitMemoryOperands = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  touchedKeys: Set<string>
): Promise<void> => {
  for (let operand = 0; operand < instruction.opCount; operand += 1) {
    if (instruction.opKind(operand) !== iced.OpKind["Memory"]) continue;
    const bits = operandBits(iced, instruction, operand);
    const addresses = bits == null ? null : resolveMemoryAddresses(iced, state, instruction);
    if (bits == null || addresses == null) continue;
    for (const address of addresses) await preloadCell(reader, opts, state, touchedKeys, address, bits);
  }
};

const preloadMovsSource = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  touchedKeys: Set<string>
): Promise<void> => {
  if (!isAnyMnemonic(iced, instruction.mnemonic, MOVS_MNEMONICS)) return;
  const source = stringPointer(iced, instruction, 1, "SI");
  const bits = memorySizeBits(iced, instruction);
  if (!source || bits == null) return;
  const count = repeatedCount(iced, state, source.bits, instruction);
  const sourceAddress = knownSingleValue(iced, state, source.registerName);
  const forward = readFlag(state, "DF") === false;
  if (count == null || count < 0n || sourceAddress == null || readFlag(state, "DF") == null) return;
  if (count > BigInt(MAX_IMAGE_MEMORY_PRELOAD_CELLS)) return;
  const bytes = movsElementBytes(bits);
  for (let index = 0n; index < count; index += 1n) {
    const offset = forward ? index * bytes : -index * bytes;
    await preloadCell(reader, opts, state, touchedKeys, sourceAddress + offset, bits);
  }
};

export const preloadImageMemoryForInstruction = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): Promise<PreloadedImageMemory> => {
  const touchedKeys = new Set<string>();
  await preloadExplicitMemoryOperands(reader, opts, iced, state, instruction, touchedKeys);
  await preloadMovsSource(reader, opts, iced, state, instruction, touchedKeys);
  return { touchedKeys };
};

export const invalidateTouchedMemory = (
  state: EmulationState,
  preloaded: PreloadedImageMemory
): void => {
  for (const key of preloaded.touchedKeys) state.memory.delete(key);
};
