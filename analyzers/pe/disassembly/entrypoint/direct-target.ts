"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import type {
  AnalyzePeEntrypointDisassemblyOptions,
  PeEntrypointInstructionTarget
} from "../types.js";
import {
  queueFollowedBlock,
  type FollowQueueState
} from "./follow-queue.js";
import type { DirectControlFlowTarget } from "./control-flow.js";
import { createCallStackState } from "./call-stack.js";
import {
  cloneEmulationState,
  type EmulationState
} from "./emulation-state.js";
import type { IcedModule } from "./iced.js";

export const followDirectCodeTarget = async (
  iced: IcedModule,
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  state: FollowQueueState,
  directTarget: DirectControlFlowTarget,
  instructionRva: number,
  nextIp: bigint,
  emulationState: EmulationState
): Promise<Extract<PeEntrypointInstructionTarget, { kind: "code" }>> => {
  const targetState = directTarget.kind === "followed-call"
    ? createCallStackState(iced, emulationState, nextIp)
    : cloneEmulationState(emulationState);
  const followed = await queueFollowedBlock(
    reader,
    opts,
    state,
    directTarget,
    instructionRva,
    targetState
  );
  return { kind: "code", rva: directTarget.rva, followed };
};
