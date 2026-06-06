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
import {
  queueFollowedBlock,
  type FollowQueueState,
  type PendingBlock
} from "./follow-queue.js";
import type { IcedModule } from "./iced.js";

export const followReturnTarget = async (
  reader: FileRangeReader,
  iced: IcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  block: PendingBlock,
  instructionRva: number,
  state: FollowQueueState,
  pending: PendingBlock[],
  issues: string[]
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
      pending,
      { kind: "followed-return", rva: target.rva },
      instructionRva,
      issues,
      createReturnStackState(iced, block.emulationState)
    )
  };
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
