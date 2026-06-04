"use strict";

type X86OpKinds = Record<string, number> & Record<number, string | undefined>;

type NearBranchInstruction = {
  op0Kind: number;
  nearBranchTarget: bigint;
  nextIP: bigint;
};

export type NearBranchEdges = {
  branchTarget: bigint;
  fallthroughTarget: bigint;
};

export const hasNearBranchOperand = (opKind: number, opKinds: X86OpKinds): boolean =>
  opKind === opKinds["NearBranch16"] ||
  opKind === opKinds["NearBranch32"] ||
  opKind === opKinds["NearBranch64"];

export const getNearBranchTarget = (
  instruction: NearBranchInstruction,
  opKinds: X86OpKinds
): bigint | null =>
  hasNearBranchOperand(instruction.op0Kind, opKinds) ? instruction.nearBranchTarget : null;

export const getNearBranchEdges = (
  instruction: NearBranchInstruction,
  opKinds: X86OpKinds
): NearBranchEdges | null => {
  const branchTarget = getNearBranchTarget(instruction, opKinds);
  if (branchTarget == null) return null;
  return {
    branchTarget,
    fallthroughTarget: instruction.nextIP
  };
};
