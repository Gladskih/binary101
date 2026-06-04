"use strict";

import type { IcedX86Module } from "../../x86/disassembly-iced.js";
import {
  getNearBranchEdges,
  getNearBranchTarget
} from "../../x86/disassembly-branch-targets.js";
import { MAX_RVA } from "./entrypoint-metadata.js";
import type { ImportTarget } from "./entrypoint-import-targets.js";
import type {
  AnalyzePeEntrypointDisassemblyOptions,
  PeEntrypointInstructionTarget
} from "./types.js";

type IcedInstruction = InstanceType<IcedX86Module["Instruction"]>;

export type DirectControlFlowTarget = {
  kind: "followed-call" | "followed-jump";
  rva: number;
};

export type ConditionalBranchTargets = {
  branch: {
    kind: "followed-branch";
    rva: number;
  };
  fallthrough: {
    kind: "followed-fallthrough";
    rva: number;
  };
};

export type FollowedCodeTarget =
  | DirectControlFlowTarget
  | ConditionalBranchTargets["branch"]
  | ConditionalBranchTargets["fallthrough"]
  | {
      kind: "followed-import-return";
      rva: number;
    }
  | {
      kind: "speculative-call-fallthrough";
      rva: number;
    };

export const toRva = (virtualAddress: bigint, imageBase: bigint): number | null => {
  if (virtualAddress < imageBase) return null;
  const delta = virtualAddress - imageBase;
  if (delta > BigInt(MAX_RVA)) return null;
  const value = Number(delta);
  return Number.isSafeInteger(value) && value >= 0 ? value >>> 0 : null;
};

export const getDirectControlFlowTarget = (
  iced: IcedX86Module,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  instruction: IcedInstruction
): DirectControlFlowTarget | null => {
  const isCall = instruction.flowControl === iced.FlowControl["Call"];
  const isJump = instruction.flowControl === iced.FlowControl["UnconditionalBranch"];
  if (!isCall && !isJump) return null;
  const target = getNearBranchTarget(instruction, iced.OpKind);
  if (target == null) return null;
  const rva = toRva(target, opts.imageBase);
  if (rva == null) return null;
  return { kind: isCall ? "followed-call" : "followed-jump", rva };
};

export const getConditionalBranchTargets = (
  iced: IcedX86Module,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  instruction: IcedInstruction
): ConditionalBranchTargets | null => {
  if (instruction.flowControl !== iced.FlowControl["ConditionalBranch"]) return null;
  const edges = getNearBranchEdges(instruction, iced.OpKind);
  if (!edges) return null;
  const branchRva = toRva(edges.branchTarget, opts.imageBase);
  const fallthroughRva = toRva(edges.fallthroughTarget, opts.imageBase);
  if (branchRva == null || fallthroughRva == null) return null;
  return {
    branch: { kind: "followed-branch", rva: branchRva },
    fallthrough: { kind: "followed-fallthrough", rva: fallthroughRva }
  };
};

export const getImportTarget = (
  iced: IcedX86Module,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  instruction: IcedInstruction,
  importTargets: Map<number, ImportTarget>
): Extract<PeEntrypointInstructionTarget, { kind: "import" }> | null => {
  const flowControl = instruction.flowControl;
  const indirectCall = flowControl === iced.FlowControl["IndirectCall"];
  const indirectJump = flowControl === iced.FlowControl["IndirectBranch"];
  if (!indirectCall && !indirectJump) return null;
  if (instruction.op0Kind !== iced.OpKind["Memory"]) return null;
  const slotRva = toRva(instruction.memoryDisplacement, opts.imageBase);
  if (slotRva == null) return null;
  const imported = importTargets.get(slotRva);
  return imported ? { kind: "import", ...imported } : null;
};
