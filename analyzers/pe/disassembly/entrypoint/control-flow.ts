"use strict";

import type { FileRangeReader } from "../../../file-range-reader.js";
import {
  getNearBranchEdges,
  getNearBranchTarget
} from "../../../x86/disassembly-branch-targets.js";
import { MAX_RVA } from "./metadata.js";
import type { ImportTarget } from "./import-targets.js";
import type { IcedInstructionObject, IcedModule } from "./iced.js";
import {
  readOperand,
  resolveMemoryAddress
} from "./emulation-operands.js";
import {
  collectKnownValues,
  type EmulationState
} from "./emulation-state.js";
import type {
  AnalyzePeEntrypointDisassemblyOptions,
  PeEntrypointInstructionTarget
} from "../types.js";

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
      kind: "followed-return";
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
  iced: IcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  instruction: IcedInstructionObject
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

export const getEmulatedIndirectControlFlowTarget = (
  iced: IcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  instruction: IcedInstructionObject,
  state: EmulationState
): DirectControlFlowTarget | null => {
  const indirectCall = instruction.flowControl === iced.FlowControl["IndirectCall"];
  const indirectJump = instruction.flowControl === iced.FlowControl["IndirectBranch"];
  if (!indirectCall && !indirectJump) return null;
  const rvas = new Set<number>();
  for (const value of collectKnownValues(readOperand(iced, state, instruction, 0))) {
    const rva = toRva(value.value, opts.imageBase);
    if (rva == null) continue;
    rvas.add(rva);
  }
  if (rvas.size !== 1) return null;
  const [rva] = rvas;
  return rva == null ? null : { kind: indirectCall ? "followed-call" : "followed-jump", rva };
};

const readPointerValue = (view: DataView): bigint => {
  let value = 0n;
  for (let offset = 0; offset < view.byteLength; offset += 1) {
    value |= BigInt(view.getUint8(offset)) << BigInt(offset * 8);
  }
  return value;
};

const pointerBytes = (opts: AnalyzePeEntrypointDisassemblyOptions): number =>
  opts.is64Bit ? 8 : 4;

export const getImageMemoryIndirectControlFlowTarget = async (
  reader: FileRangeReader,
  iced: IcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  instruction: IcedInstructionObject,
  state: EmulationState,
  issues: string[]
): Promise<DirectControlFlowTarget | null> => {
  const indirectCall = instruction.flowControl === iced.FlowControl["IndirectCall"];
  const indirectJump = instruction.flowControl === iced.FlowControl["IndirectBranch"];
  if (!indirectCall && !indirectJump) return null;
  if (instruction.op0Kind !== iced.OpKind["Memory"]) return null;
  const slotAddress = resolveMemoryAddress(iced, state, instruction);
  if (slotAddress == null) return null;
  const slotRva = toRva(slotAddress, opts.imageBase);
  if (slotRva == null) return null;
  const fileOffset = opts.rvaToOff(slotRva);
  const size = pointerBytes(opts);
  if (
    fileOffset == null ||
    !Number.isSafeInteger(fileOffset) ||
    fileOffset < 0 ||
    fileOffset > reader.size - size
  ) return null;
  try {
    const view = await reader.read(fileOffset, size);
    if (view.byteLength !== size) return null;
    const rva = toRva(readPointerValue(view), opts.imageBase);
    return rva == null ? null : { kind: indirectCall ? "followed-call" : "followed-jump", rva };
  } catch (error) {
    issues.push(`Indirect memory target slot could not be read (${String(error)})`);
    return null;
  }
};

export const getConditionalBranchTargets = (
  iced: IcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  instruction: IcedInstructionObject
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
  iced: IcedModule,
  opts: AnalyzePeEntrypointDisassemblyOptions,
  instruction: IcedInstructionObject,
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
