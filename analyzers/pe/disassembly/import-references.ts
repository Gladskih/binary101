"use strict";

import type { IcedInstructionObject, IcedX86Module } from "../../x86/disassembly-iced.js";
import type { PeDelayImportEntry } from "../imports/delay.js";
import type { PeImportParseResult } from "../imports/index.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";
import type { PeDirectIatReferenceCount } from "./types.js";

const INVALID_SLOT_RANGE_ISSUE =
  "Import IAT slot falls outside the 32-bit RVA range and was skipped.";

export type PeDirectIatReferenceCounter = {
  record(instruction: IcedInstructionObject): void;
  references(): PeDirectIatReferenceCount[];
};

type DirectIatReferenceKind = "call" | "jump";

type DirectIatReference = {
  kind: DirectIatReferenceKind;
  slotRva: number;
};

export const getIatSlotRva = (
  startRva: unknown,
  index: number,
  entrySize: number
): number | null => {
  if (
    !Number.isSafeInteger(startRva) ||
    (startRva as number) <= 0 ||
    !Number.isSafeInteger(index) ||
    index < 0 ||
    (entrySize !== Uint32Array.BYTES_PER_ELEMENT &&
      entrySize !== BigUint64Array.BYTES_PER_ELEMENT)
  ) return null;
  const slotRva = (startRva as number) + index * entrySize;
  if (
    !Number.isSafeInteger(slotRva) ||
    slotRva < 0 ||
    slotRva > PE_RVA_EXCLUSIVE_LIMIT - entrySize
  ) return null;
  return slotRva >>> 0;
};

const addSlotRange = (
  slots: Set<number>,
  startRva: unknown,
  functionCount: number,
  entrySize: number,
  issues: string[]
): void => {
  if (!Number.isSafeInteger(startRva) || (startRva as number) <= 0) return;
  let invalidRange = false;
  for (let index = 0; index < functionCount; index += 1) {
    const slotRva = getIatSlotRva(startRva, index, entrySize);
    if (slotRva == null) {
      invalidRange = true;
      continue;
    }
    slots.add(slotRva);
  }
  if (invalidRange) {
    if (!issues.includes(INVALID_SLOT_RANGE_ISSUE)) issues.push(INVALID_SLOT_RANGE_ISSUE);
  }
};

const addEagerSlots = (
  slots: Set<number>,
  imports: PeImportParseResult | undefined,
  entrySize: number,
  issues: string[]
): void => {
  if (!Array.isArray(imports?.entries)) return;
  if (imports.thunkEntrySize !== entrySize) {
    issues.push(
      `Import thunk size ${imports.thunkEntrySize} does not match ${entrySize}-byte image pointers; ` +
      "IAT slots were derived from image bitness."
    );
  }
  for (const entry of imports.entries) {
    if (!entry || !Array.isArray(entry.functions)) continue;
    addSlotRange(slots, entry.firstThunkRva, entry.functions.length, entrySize, issues);
  }
};

const addDelaySlots = (
  slots: Set<number>,
  delayImports: { entries: PeDelayImportEntry[] } | null | undefined,
  entrySize: number,
  issues: string[]
): void => {
  if (!Array.isArray(delayImports?.entries)) return;
  for (const entry of delayImports.entries) {
    if (!entry || !Array.isArray(entry.functions)) continue;
    addSlotRange(slots, entry.ImportAddressTableRVA, entry.functions.length, entrySize, issues);
  }
};

export const collectDirectIatSlotRvas = (
  is64Bit: boolean,
  imports: PeImportParseResult | undefined,
  delayImports: { entries: PeDelayImportEntry[] } | null | undefined,
  issues: string[]
): Set<number> => {
  const slots = new Set<number>();
  const entrySize = is64Bit
    ? BigUint64Array.BYTES_PER_ELEMENT
    : Uint32Array.BYTES_PER_ELEMENT;
  addEagerSlots(slots, imports, entrySize, issues);
  addDelaySlots(slots, delayImports, entrySize, issues);
  return slots;
};

const directMemoryAddress = (
  iced: IcedX86Module,
  instruction: IcedInstructionObject
): bigint | null => {
  if (instruction.op0Kind !== iced.OpKind["Memory"]) return null;
  const noRegister = iced.Register?.["None"];
  if (noRegister == null) return null;
  if (instruction.memoryIndex !== noRegister) return null;
  const directAbsolute = instruction.memoryBase === noRegister;
  const ipRelativeBase =
    instruction.memoryBase === iced.Register?.["EIP"] ||
    instruction.memoryBase === iced.Register?.["RIP"];
  if (instruction.isIpRelMemoryOperand !== ipRelativeBase) return null;
  if (!directAbsolute && !ipRelativeBase) return null;
  return instruction.memoryDisplacement;
};

const directIatReferenceKind = (
  iced: IcedX86Module,
  instruction: IcedInstructionObject
): DirectIatReferenceKind | null => {
  if (instruction.isCallNearIndirect) {
    if (
      instruction.isJmpNearIndirect ||
      instruction.flowControl !== iced.FlowControl["IndirectCall"]
    ) return null;
    return "call";
  }
  if (
    !instruction.isJmpNearIndirect ||
    instruction.flowControl !== iced.FlowControl["IndirectBranch"]
  ) return null;
  return "jump";
};

const directIatReference = (
  iced: IcedX86Module,
  imageBase: bigint,
  instruction: IcedInstructionObject
): DirectIatReference | null => {
  const kind = directIatReferenceKind(iced, instruction);
  if (kind == null) return null;
  const address = directMemoryAddress(iced, instruction);
  if (address == null || address < imageBase) return null;
  const delta = address - imageBase;
  if (delta >= BigInt(PE_RVA_EXCLUSIVE_LIMIT)) return null;
  const rva = Number(delta);
  return Number.isSafeInteger(rva) ? { kind, slotRva: rva >>> 0 } : null;
};

export const createDirectIatReferenceCounter = (
  iced: IcedX86Module,
  imageBase: bigint,
  slots: ReadonlySet<number>
): PeDirectIatReferenceCounter => {
  const counts = new Map<number, PeDirectIatReferenceCount>();
  return {
    record: instruction => {
      const reference = directIatReference(iced, imageBase, instruction);
      if (reference == null || !slots.has(reference.slotRva)) return;
      const current = counts.get(reference.slotRva);
      counts.set(reference.slotRva, {
        slotRva: reference.slotRva,
        callReferenceCount: reference.kind === "call"
          ? (current?.callReferenceCount ?? 0) + 1
          : current?.callReferenceCount ?? 0,
        jumpReferenceCount: reference.kind === "jump"
          ? (current?.jumpReferenceCount ?? 0) + 1
          : current?.jumpReferenceCount ?? 0
      });
    },
    references: () => [...counts]
      .sort(([left], [right]) => left - right)
      .map(([, reference]) => reference)
  };
};
