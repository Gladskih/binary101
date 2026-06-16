"use strict";

import type { PeEntrypointInstruction } from "../../../types.js";
import type { IcedInstructionObject, IcedModule } from "../../iced.js";
import type { EmulationState } from "../state.js";
import {
  executeDataMovement,
  executeLogical
} from "./data.js";
import { executeArithmetic } from "./arithmetic.js";
import {
  executeBitScanAndCount,
  executeDoubleShift,
  executeShift
} from "./bits.js";
import {
  executeAccumulatorExtension,
  executeCompareExchange,
  executeConditionalWrites,
  executeExchange,
} from "./effects.js";
import { executeFlagControl } from "../flag-control.js";
import { executeCounterControlFlow } from "../counter-control.js";
import { executeMultiplyDivide } from "./multiply.js";

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
  executeFlagControl(iced, state, instruction) ||
  executeCounterControlFlow(iced, state, instruction) ||
  executeAccumulatorExtension(iced, state, instruction) ||
  executeBitScanAndCount(iced, state, instruction) ||
  executeMultiplyDivide(iced, state, instruction);
