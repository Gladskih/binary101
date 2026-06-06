"use strict";

import type { EntrypointIcedModule, IcedInstruction } from "./entrypoint-iced.js";

export type EntrypointImmediateOperand = {
  operand: number;
  value: bigint;
};

const isImmediateOperand = (
  opKinds: EntrypointIcedModule["OpKind"],
  kind: number
): boolean =>
  kind === opKinds["Immediate8"] ||
  kind === opKinds["Immediate8_2nd"] ||
  kind === opKinds["Immediate16"] ||
  kind === opKinds["Immediate32"] ||
  kind === opKinds["Immediate64"] ||
  kind === opKinds["Immediate8to16"] ||
  kind === opKinds["Immediate8to32"] ||
  kind === opKinds["Immediate8to64"] ||
  kind === opKinds["Immediate32to64"];

const readImmediateOperand = (
  instruction: IcedInstruction,
  operand: number
): bigint | null => {
  try {
    return BigInt.asUintN(64, instruction.immediate(operand));
  } catch {
    return null;
  }
};

export const collectImmediateOperands = (
  iced: EntrypointIcedModule,
  instruction: IcedInstruction
): EntrypointImmediateOperand[] => {
  const operands: EntrypointImmediateOperand[] = [];
  for (let operand = 0; operand < instruction.opCount; operand += 1) {
    if (!isImmediateOperand(iced.OpKind, instruction.opKind(operand))) continue;
    const value = readImmediateOperand(instruction, operand);
    if (value != null) operands.push({ operand, value });
  }
  return operands;
};
