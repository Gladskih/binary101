"use strict";

import type { AnalyzePeEntrypointDisassemblyOptions } from "../types.js";
import { toRva } from "./control-flow.js";
import {
  UNKNOWN,
  cloneEmulationState,
  known,
  readRegister,
  writeRegister,
  type EmulationState
} from "./emulation/state.js";
import { resolveStackPointer } from "./emulation/operands.js";
import type { IcedModule } from "./iced.js";

export type StackReturnTarget =
  | {
      kind: "known";
      rva: number;
    }
  | {
      kind: "outside-image";
    }
  | {
      kind: "unknown";
    };

// Near CALL pushes the next instruction address and near RET pops the return
// address from the stack. Intel SDM Vol. 1, Ch. 6 and Vol. 2 CALL/RET.
// https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
const pointerBytes = (state: EmulationState): bigint => BigInt(state.bitness / 8);

const stackSlotAddress = (slot: string): bigint | null => {
  try {
    return BigInt(slot);
  } catch {
    return null;
  }
};

const deleteStackMemoryRange = (
  state: EmulationState,
  start: bigint,
  byteCount: bigint
): void => {
  const end = start + byteCount;
  for (const slot of Array.from(state.memory.keys())) {
    const address = stackSlotAddress(slot);
    if (address != null && address >= start && address < end) state.memory.delete(slot);
  }
};

export const createCallStackState = (
  iced: IcedModule,
  state: EmulationState,
  returnAddress: bigint
): EmulationState => {
  const next = cloneEmulationState(state);
  const stackPointer = resolveStackPointer(iced, next);
  const current = readRegister(next, stackPointer);
  if (current.kind !== "known") {
    writeRegister(next, stackPointer, UNKNOWN);
    return next;
  }
  const stackSlot = known(current.value - pointerBytes(next), next.bitness);
  writeRegister(next, stackPointer, stackSlot);
  next.memory.set(stackSlot.value.toString(), known(returnAddress, next.bitness));
  return next;
};

export const createReturnStackState = (
  iced: IcedModule,
  state: EmulationState,
  immediateBytes = 0n,
  returnFrameBytes?: bigint
): EmulationState => {
  const next = cloneEmulationState(state);
  const stackPointer = resolveStackPointer(iced, next);
  const current = readRegister(next, stackPointer);
  if (current.kind !== "known") {
    writeRegister(next, stackPointer, UNKNOWN);
    return next;
  }
  const consumedBytes = (returnFrameBytes ?? pointerBytes(next)) + immediateBytes;
  deleteStackMemoryRange(next, current.value, consumedBytes);
  writeRegister(
    next,
    stackPointer,
    known(current.value + consumedBytes, next.bitness)
  );
  return next;
};

export const getStackReturnTarget = (
  iced: IcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  state: EmulationState
): StackReturnTarget => {
  const stackPointer = resolveStackPointer(iced, state);
  const current = readRegister(state, stackPointer);
  if (current.kind !== "known") return { kind: "unknown" };
  const target = state.memory.get(current.value.toString());
  if (target?.kind !== "known") return { kind: "unknown" };
  const rva = toRva(target.value, opts.imageBase);
  return rva == null ? { kind: "outside-image" } : { kind: "known", rva };
};
