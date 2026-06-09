"use strict";

import type { PeEntrypointInstruction } from "../types.js";
import type { IcedInstructionObject, IcedModule } from "./iced.js";
import type { EmulationState } from "./emulation-state.js";
import {
  executeArithmetic,
  executeDataMovement,
  executeLogical
} from "./emulation-integer-data.js";
import {
  executeBitScanAndCount,
  executeDoubleShift,
  executeShift
} from "./emulation-integer-bits.js";
import {
  executeAccumulatorExtension,
  executeCompareExchange,
  executeConditionalWrites,
  executeExchange
} from "./emulation-integer-effects.js";
import { executeMultiplyDivide } from "./emulation-integer-multiply.js";

export const executeIntegerInstruction = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  rendered: PeEntrypointInstruction
): boolean =>
  executeDataMovement(iced, state, instruction) ||
  executeLogical(iced, state, rendered, instruction) ||
  executeArithmetic(iced, state, instruction) ||
  executeShift(iced, state, instruction) ||
  executeDoubleShift(iced, state, instruction) ||
  executeExchange(iced, state, instruction) ||
  executeCompareExchange(iced, state, instruction) ||
  executeConditionalWrites(iced, state, instruction) ||
  executeAccumulatorExtension(iced, state, instruction) ||
  executeBitScanAndCount(iced, state, instruction) ||
  executeMultiplyDivide(iced, state, instruction);
