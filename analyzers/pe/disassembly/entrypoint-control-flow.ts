"use strict";

import type { IcedX86Module } from "../../x86/disassembly-iced.js";
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

export const toRva = (virtualAddress: bigint, imageBase: bigint): number | null => {
  if (virtualAddress < imageBase) return null;
  const delta = virtualAddress - imageBase;
  if (delta > BigInt(MAX_RVA)) return null;
  const value = Number(delta);
  return Number.isSafeInteger(value) && value >= 0 ? value >>> 0 : null;
};

const isNearBranch = (iced: IcedX86Module, instruction: IcedInstruction): boolean =>
  instruction.op0Kind === iced.OpKind["NearBranch16"] ||
  instruction.op0Kind === iced.OpKind["NearBranch32"] ||
  instruction.op0Kind === iced.OpKind["NearBranch64"];

export const getDirectControlFlowTarget = (
  iced: IcedX86Module,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  instruction: IcedInstruction
): DirectControlFlowTarget | null => {
  const isCall = instruction.flowControl === iced.FlowControl["Call"];
  const isJump = instruction.flowControl === iced.FlowControl["UnconditionalBranch"];
  if ((!isCall && !isJump) || !isNearBranch(iced, instruction)) return null;
  const rva = toRva(instruction.nearBranchTarget, opts.imageBase);
  if (rva == null) return null;
  return { kind: isCall ? "followed-call" : "followed-jump", rva };
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
