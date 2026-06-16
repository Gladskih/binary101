"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import type {
  AnalyzePeEntrypointDisassemblyOptions,
  PeEntrypointInstruction
} from "../types.js";
import {
  getConditionalBranchTargets,
  getDirectControlFlowTarget,
  getEmulatedIndirectControlFlowTarget,
  getImageMemoryIndirectControlFlowTarget,
  getImportTarget,
  type ConditionalBranchTargets,
  type DirectControlFlowTarget
} from "./control-flow.js";
import {
  getReturningImportFallthrough,
  type ReturningImportFallthrough
} from "./import-fallthrough.js";
import {
  getGuardFallthrough,
  type GuardFallthrough
} from "./guard-fallthrough.js";
import {
  getUnknownIndirectCallFallthrough,
  type IndirectCallFallthrough
} from "./indirect-call-fallthrough.js";
import {
  followDirectCodeTarget
} from "./direct-target.js";
import type { ImportTarget } from "./import-targets.js";
import { createReturnStackState } from "./call-stack.js";
import { applyReturningImportEffects } from "./import-effects.js";
import type { EmulationState } from "./emulation/state.js";
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
  guardFallthrough: GuardFallthrough | null;
  unknownIndirectCallFallthrough: IndirectCallFallthrough | null;
};

const createImportReturnState = (
  iced: IcedModule,
  emulationState: EmulationState,
  importTarget: ImportTarget
): EmulationState => {
  const returned = createReturnStackState(iced, emulationState);
  applyReturningImportEffects(iced, returned, importTarget);
  return returned;
};

const applyImportTarget = async (
  reader: FileRangeReader,
  iced: IcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  state: FollowQueueState,
  block: PendingBlock,
  instruction: PeEntrypointInstruction,
  importTarget: ImportTarget,
  importFallthrough: ReturningImportFallthrough | null
): Promise<void> => {
  const returnFollowed = importFallthrough?.kind === "stack-return"
    ? await queueFollowedBlock(
      reader,
      opts,
      state,
      { kind: "followed-import-return", rva: importFallthrough.rva },
      instruction.rva,
      createImportReturnState(iced, block.emulationState, importTarget)
    )
    : importFallthrough?.kind === "current-block";
  if (importFallthrough?.kind === "current-block") {
    applyReturningImportEffects(iced, block.emulationState, importTarget);
  }
  instruction.target = importFallthrough == null
    ? { kind: "import", ...importTarget }
    : { kind: "import", ...importTarget, returnRva: importFallthrough.rva, returnFollowed };
};

const applyDirectTarget = async (
  reader: FileRangeReader,
  iced: IcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  state: FollowQueueState,
  block: PendingBlock,
  instruction: PeEntrypointInstruction,
  directTarget: DirectControlFlowTarget,
  decoded: IcedInstructionObject
): Promise<void> => {
  instruction.target = await followDirectCodeTarget(
    iced,
    reader,
    opts,
    state,
    directTarget,
    instruction.rva,
    decoded.nextIP,
    block.emulationState
  );
};

const applyBranchTarget = async (
  reader: FileRangeReader,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  state: FollowQueueState,
  block: PendingBlock,
  instruction: PeEntrypointInstruction,
  branchTargets: ConditionalBranchTargets,
  rva: number
): Promise<void> => {
  const followed = await queueConditionalBranch(
    reader,
    opts,
    state,
    branchTargets,
    rva,
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
  state: FollowQueueState,
  block: PendingBlock,
  decoded: IcedInstructionObject,
  instruction: PeEntrypointInstruction,
  importTargets: Map<number, ImportTarget>
): Promise<InstructionTargetingResult> => {
  const importTarget = getImportTarget(iced, opts, decoded, importTargets);
  const directTarget = getDirectControlFlowTarget(iced, opts, decoded) ??
    getEmulatedIndirectControlFlowTarget(iced, opts, decoded, block.emulationState) ??
    await getImageMemoryIndirectControlFlowTarget(
      reader,
      iced,
      opts,
      decoded,
      block.emulationState,
      state.issues
    );
  const branchTargets = getConditionalBranchTargets(iced, opts, decoded, block.emulationState);
  const importFallthrough = getReturningImportFallthrough(
    iced,
    opts,
    block.mapped,
    decoded,
    importTarget,
    block.emulationState
  );
  const guardFallthrough = getGuardFallthrough(iced, opts, block.mapped, decoded);
  const unknownIndirectCallFallthrough = importTarget || guardFallthrough || directTarget
    ? null
    : getUnknownIndirectCallFallthrough(iced, opts, block.mapped, decoded);
  if (importTarget) {
    await applyImportTarget(
      reader,
      iced,
      opts,
      state,
      block,
      instruction,
      importTarget,
      importFallthrough
    );
  } else if (guardFallthrough) {
    instruction.notes = [
      ...(instruction.notes ?? []),
      "CFG guard function pointer call is treated as returning."
    ];
  } else if (unknownIndirectCallFallthrough) {
    instruction.notes = [
      ...(instruction.notes ?? []),
      "Unknown indirect call target; preview continues at fallthrough."
    ];
  } else if (directTarget) {
    await applyDirectTarget(
      reader,
      iced,
      opts,
      state,
      block,
      instruction,
      directTarget,
      decoded
    );
  } else if (branchTargets) {
    await applyBranchTarget(
      reader,
      opts,
      state,
      block,
      instruction,
      branchTargets,
      instruction.rva
    );
  } else if (decoded.flowControl === iced.FlowControl["Return"]) {
    instruction.target = await followReturnTarget(
      reader,
      iced,
      opts,
      block,
      decoded,
      instruction.rva,
      state
    );
  }
  return {
    importTarget,
    directTarget,
    branchTargets,
    importFallthrough,
    guardFallthrough,
    unknownIndirectCallFallthrough
  };
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
  if (targets.guardFallthrough) {
    return "Entrypoint preview continued after CFG guard function pointer call.";
  }
  if (targets.unknownIndirectCallFallthrough) {
    return "Entrypoint preview continued after unknown indirect call.";
  }
  if (directTarget && instruction.target?.kind === "code" && instruction.target.followed) {
    return `Entrypoint preview followed ${directTarget.kind.replace("followed-", "")} target.`;
  }
  if (instruction.target?.kind === "branch") {
    return "Entrypoint preview followed conditional branch target(s).";
  }
  if (instruction.target?.kind === "return") return returnIssue(instruction.target);
  return `Entrypoint preview stopped at control-flow instruction '${instruction.text}'.`;
};
