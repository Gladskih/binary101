"use strict";

import type { IcedModule, IcedInstructionObject } from "./iced.js";

export type ImmediateOperand = {
  operand: number;
  value: bigint;
};

const isImmediateOperand = (
  opKinds: IcedModule["OpKind"],
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
  instruction: IcedInstructionObject,
  operand: number
): bigint | null => {
  try {
    return BigInt.asUintN(64, instruction.immediate(operand));
  } catch {
    return null;
  }
};

export const collectImmediateOperands = (
  iced: IcedModule,
  instruction: IcedInstructionObject
): ImmediateOperand[] => {
  const operands: ImmediateOperand[] = [];
  for (let operand = 0; operand < instruction.opCount; operand += 1) {
    if (!isImmediateOperand(iced.OpKind, instruction.opKind(operand))) continue;
    const value = readImmediateOperand(instruction, operand);
    if (value != null) operands.push({ operand, value });
  }
  return operands;
};
