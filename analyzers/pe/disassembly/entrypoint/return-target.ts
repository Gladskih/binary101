"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import type {
  AnalyzePeEntrypointDisassemblyOptions,
  PeEntrypointInstructionTarget
} from "../types.js";
import {
  createReturnStackState,
  getStackReturnTarget
} from "./call-stack.js";
import { collectImmediateOperands } from "./immediate-operands.js";
import {
  queueFollowedBlock,
  type FollowQueueState,
  type PendingBlock
} from "./follow-queue.js";
import type { IcedModule } from "./iced.js";
import type { IcedInstructionObject } from "./iced.js";

export const followReturnTarget = async (
  reader: FileRangeReader,
  iced: IcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  block: PendingBlock,
  instruction: IcedInstructionObject,
  instructionRva: number,
  state: FollowQueueState
): Promise<Extract<PeEntrypointInstructionTarget, { kind: "return" }>> => {
  const target = getStackReturnTarget(iced, opts, block.emulationState);
  if (target.kind !== "known") return { kind: "return", reason: target.kind };
  return {
    kind: "return",
    rva: target.rva,
    followed: await queueFollowedBlock(
      reader,
      opts,
      state,
      { kind: "followed-return", rva: target.rva },
      instructionRva,
      createReturnStackState(
        iced,
        block.emulationState,
        returnImmediateBytes(iced, instruction),
        returnFrameBytes(iced, instruction, block.emulationState.bitness)
      )
    )
  };
};

const returnImmediateBytes = (
  iced: IcedModule,
  instruction: IcedInstructionObject
): bigint =>
  collectImmediateOperands(iced, instruction)[0]?.value ?? 0n;

const isCode = (
  iced: IcedModule,
  instruction: IcedInstructionObject,
  name: string
): boolean => instruction.code === iced.Code[name];

const isAnyCode = (
  iced: IcedModule,
  instruction: IcedInstructionObject,
  names: readonly string[]
): boolean => names.some(name => isCode(iced, instruction, name));

// Intel SDM Vol. 2 RET: operand size selects 16/32/64-bit return offset pops;
// far returns pop both the offset and CS before the optional imm16 release.
// https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
const returnOffsetBytes = (
  iced: IcedModule,
  instruction: IcedInstructionObject,
  bitness: 32 | 64
): bigint => {
  if (isAnyCode(iced, instruction, ["Retnq", "Retnq_imm16", "Retfq", "Retfq_imm16"])) {
    return 8n;
  }
  if (isAnyCode(iced, instruction, ["Retnw", "Retnw_imm16", "Retfw", "Retfw_imm16"])) {
    return 2n;
  }
  if (isAnyCode(iced, instruction, ["Retnd", "Retnd_imm16", "Retfd", "Retfd_imm16"])) {
    return 4n;
  }
  return BigInt(bitness / 8);
};

const returnFrameBytes = (
  iced: IcedModule,
  instruction: IcedInstructionObject,
  bitness: 32 | 64
): bigint => {
  const bytes = returnOffsetBytes(iced, instruction, bitness);
  return instruction.mnemonic === iced.Mnemonic?.["Retf"] ? bytes * 2n : bytes;
};

export const returnIssue = (
  target: Extract<PeEntrypointInstructionTarget, { kind: "return" }>
): string => {
  if ("rva" in target) return "Entrypoint preview followed return target from stack.";
  if (target.reason === "outside-image") {
    return "Entrypoint preview stopped at return target outside the PE image.";
  }
  return "Entrypoint preview stopped at return with unknown stack target.";
};
