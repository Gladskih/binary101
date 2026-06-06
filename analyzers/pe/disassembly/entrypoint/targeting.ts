"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import type {
  AnalyzePeEntrypointDisassemblyOptions,
  PeEntrypointInstruction
} from "../types.js";
import {
  getConditionalBranchTargets,
  getDirectControlFlowTarget,
  getImportTarget,
  type ConditionalBranchTargets,
  type DirectControlFlowTarget
} from "./control-flow.js";
import {
  getReturningImportFallthrough,
  type ReturningImportFallthrough
} from "./import-fallthrough.js";
import { followDirectCodeTarget } from "./direct-target.js";
import type { ImportTarget } from "./import-targets.js";
import { createReturnStackState } from "./call-stack.js";
import {
  queueConditionalBranch,
  queueFollowedBlock,
  type FollowQueueState,
  type PendingBlock
} from "./follow-queue.js";
import { followReturnTarget, returnIssue } from "./return-target.js";
import type { IcedInstructionObject, IcedModule } from "./iced.js";

export type InstructionTargetingResult = {
  importTarget: ImportTarget | null;
  directTarget: DirectControlFlowTarget | null;
  branchTargets: ConditionalBranchTargets | null;
  importFallthrough: ReturningImportFallthrough | null;
};

const applyImportTarget = async (
  reader: FileRangeReader,
  iced: IcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  block: PendingBlock,
  instruction: PeEntrypointInstruction,
  importTarget: ImportTarget,
  importFallthrough: ReturningImportFallthrough | null,
  rva: number,
  state: FollowQueueState,
  pending: PendingBlock[],
  issues: string[]
): Promise<void> => {
  const returnFollowed = importFallthrough?.kind === "stack-return"
    ? await queueFollowedBlock(
      reader,
      opts,
      state,
      pending,
      { kind: "followed-import-return", rva: importFallthrough.rva },
      rva,
      issues,
      createReturnStackState(iced, block.emulationState)
    )
    : importFallthrough?.kind === "current-block";
  instruction.target = importFallthrough == null
    ? { kind: "import", ...importTarget }
    : { kind: "import", ...importTarget, returnRva: importFallthrough.rva, returnFollowed };
};

const applyDirectTarget = async (
  reader: FileRangeReader,
  iced: IcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  block: PendingBlock,
  instruction: PeEntrypointInstruction,
  directTarget: DirectControlFlowTarget,
  decoded: IcedInstructionObject,
  rva: number,
  state: FollowQueueState,
  pending: PendingBlock[],
  issues: string[]
): Promise<void> => {
  instruction.target = await followDirectCodeTarget(
    iced,
    reader,
    opts,
    state,
    pending,
    directTarget,
    rva,
    decoded.nextIP,
    block.emulationState,
    issues
  );
};

const applyBranchTarget = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  block: PendingBlock,
  instruction: PeEntrypointInstruction,
  branchTargets: ConditionalBranchTargets,
  rva: number,
  state: FollowQueueState,
  pending: PendingBlock[],
  issues: string[]
): Promise<void> => {
  const followed = await queueConditionalBranch(
    reader,
    opts,
    state,
    pending,
    branchTargets,
    rva,
    issues,
    block.emulationState
  );
  instruction.target = {
    kind: "branch",
    branchRva: branchTargets.branch.rva,
    branchFollowed: followed.branchFollowed,
    fallthroughRva: branchTargets.fallthrough.rva,
    fallthroughFollowed: followed.fallthroughFollowed
  };
};

export const applyInstructionTargets = async (
  reader: FileRangeReader,
  iced: IcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  block: PendingBlock,
  decoded: IcedInstructionObject,
  instruction: PeEntrypointInstruction,
  importTargets: Map<number, ImportTarget>,
  rva: number,
  state: FollowQueueState,
  pending: PendingBlock[],
  issues: string[]
): Promise<InstructionTargetingResult> => {
  const importTarget = getImportTarget(iced, opts, decoded, importTargets);
  const directTarget = getDirectControlFlowTarget(iced, opts, decoded);
  const branchTargets = getConditionalBranchTargets(iced, opts, decoded);
  const importFallthrough = getReturningImportFallthrough(
    iced,
    opts,
    block.mapped,
    decoded,
    importTarget,
    block.emulationState
  );
  if (importTarget) {
    await applyImportTarget(
      reader,
      iced,
      opts,
      block,
      instruction,
      importTarget,
      importFallthrough,
      rva,
      state,
      pending,
      issues
    );
  } else if (directTarget) {
    await applyDirectTarget(
      reader,
      iced,
      opts,
      block,
      instruction,
      directTarget,
      decoded,
      rva,
      state,
      pending,
      issues
    );
  } else if (branchTargets) {
    await applyBranchTarget(reader, opts, block, instruction, branchTargets, rva, state, pending, issues);
  } else if (decoded.flowControl === iced.FlowControl["Return"]) {
    instruction.target = await followReturnTarget(reader, iced, opts, block, rva, state, pending, issues);
  }
  return { importTarget, directTarget, branchTargets, importFallthrough };
};

export const controlFlowIssue = (
  instruction: PeEntrypointInstruction,
  targets: InstructionTargetingResult
): string => {
  const { importTarget, directTarget } = targets;
  if (importTarget && instruction.target?.kind === "import" && instruction.target.returnFollowed) {
    return `Entrypoint preview continued after returning import '${importTarget.label}'.`;
  }
  if (importTarget) return `Entrypoint preview stopped at imported target '${importTarget.label}'.`;
  if (directTarget && instruction.target?.kind === "code" && instruction.target.followed) {
    return `Entrypoint preview followed ${directTarget.kind.replace("followed-", "")} target.`;
  }
  if (instruction.target?.kind === "branch") {
    return "Entrypoint preview followed conditional branch target(s).";
  }
  if (instruction.target?.kind === "return") return returnIssue(instruction.target);
  return `Entrypoint preview stopped at control-flow instruction '${instruction.text}'.`;
};
