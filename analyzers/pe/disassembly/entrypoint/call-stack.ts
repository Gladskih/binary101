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
} from "./emulation-state.js";
import { resolveStackPointer } from "./emulation-operands.js";
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
  immediateBytes = 0n
): EmulationState => {
  const next = cloneEmulationState(state);
  const stackPointer = resolveStackPointer(iced, next);
  const current = readRegister(next, stackPointer);
  if (current.kind !== "known") {
    writeRegister(next, stackPointer, UNKNOWN);
    return next;
  }
  next.memory.delete(current.value.toString());
  const bytes = pointerBytes(next);
  for (let offset = bytes; offset < bytes + immediateBytes; offset += bytes) {
    next.memory.delete((current.value + offset).toString());
  }
  writeRegister(
    next,
    stackPointer,
    known(current.value + bytes + immediateBytes, next.bitness)
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
