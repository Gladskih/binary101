"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type {
  AnalyzePeEntrypointDisassemblyOptions,
  PeEntrypointInstructionTarget
} from "./types.js";
import {
  queueFollowedBlock,
  type FollowQueueState,
  type PendingEntrypointBlock
} from "./entrypoint-follow-queue.js";
import {
  toRva,
  type DirectControlFlowTarget
} from "./entrypoint-control-flow.js";

export const followDirectCodeTarget = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  state: FollowQueueState,
  pending: PendingEntrypointBlock[],
  directTarget: DirectControlFlowTarget,
  instructionRva: number,
  nextIp: bigint,
  issues: string[]
): Promise<Extract<PeEntrypointInstructionTarget, { kind: "code" }>> => {
  const returnRva = directTarget.kind === "followed-call"
    ? toRva(nextIp, opts.imageBase)
    : null;
  const followed = await queueFollowedBlock(
    reader,
    opts,
    state,
    pending,
    directTarget,
    instructionRva,
    issues,
    returnRva
  );
  if (directTarget.kind !== "followed-call" || returnRva == null) {
    return { kind: "code", rva: directTarget.rva, followed };
  }
  return {
    kind: "code",
    rva: directTarget.rva,
    followed,
    fallthroughRva: returnRva,
    fallthroughFollowed: await queueFollowedBlock(
      reader,
      opts,
      state,
      pending,
      { kind: "speculative-call-fallthrough", rva: returnRva },
      instructionRva,
      issues
    ),
    fallthroughKind: "speculative-call-return"
  };
};
