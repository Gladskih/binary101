"use strict";

import type { PeImportMetadataParameter } from "../../../pe-import-metadata-schema.js";
import type { IcedInstructionObject, IcedX86Module } from "../../x86/disassembly-iced.js";
import type { PeApiStringEncoding } from "./types.js";
import {
  peApiStringAddressToRva,
  type PeApiStringAddressSource,
  type PeApiStringImportTarget,
  type PeApiStringPendingReference,
  type PeApiStringRecentInstruction
} from "./api-string-reference-model.js";

const X64_ARGUMENT_REGISTERS = ["RCX", "RDX", "R8", "R9"] as const;

const isDirectMemoryOperand = (
  iced: IcedX86Module,
  instruction: IcedInstructionObject,
  operand: number
): boolean => {
  if (instruction.opKind(operand) !== iced.OpKind["Memory"]) return false;
  const noRegister = iced.Register?.["None"];
  if (noRegister == null || instruction.memoryIndex !== noRegister) return false;
  const directAbsolute = instruction.memoryBase === noRegister;
  const ipRelativeBase =
    instruction.memoryBase === iced.Register?.["EIP"] ||
    instruction.memoryBase === iced.Register?.["RIP"];
  if (!directAbsolute && !ipRelativeBase) return false;
  return instruction.isIpRelMemoryOperand === ipRelativeBase;
};

const memoryAddress = (
  iced: IcedX86Module,
  instruction: IcedInstructionObject,
  operand: number
): bigint | null =>
  isDirectMemoryOperand(iced, instruction, operand) ? instruction.memoryDisplacement : null;

const readImmediate = (
  instruction: IcedInstructionObject,
  operand: number
): bigint | null => {
  try {
    return BigInt.asUintN(64, instruction.immediate(operand));
  } catch {
    return null;
  }
};

const collectImmediateOperands = (
  instruction: IcedInstructionObject
): Map<number, bigint> => {
  const values = new Map<number, bigint>();
  for (let operand = 0; operand < instruction.opCount; operand += 1) {
    const value = readImmediate(instruction, operand);
    if (value != null) values.set(operand, value);
  }
  return values;
};

export const summarizePeApiStringInstruction = (
  iced: IcedX86Module,
  instruction: IcedInstructionObject
): PeApiStringRecentInstruction => ({
  ip: instruction.ip,
  nextIp: instruction.nextIP,
  mnemonic: iced.Mnemonic?.[instruction.mnemonic],
  destinationRegister: instruction.opCount > 0
    ? iced.Register?.[instruction.opRegister(0)]
    : undefined,
  immediateOperands: collectImmediateOperands(instruction),
  memoryAddress: Array.from({ length: instruction.opCount }, (_value, operand) => operand)
    .map(operand => memoryAddress(iced, instruction, operand))
    .find((address): address is bigint => address != null) ?? null
});

const isCallInstruction = (
  iced: IcedX86Module,
  instruction: IcedInstructionObject
): boolean =>
  instruction.isCallNearIndirect &&
  !instruction.isJmpNearIndirect &&
  instruction.flowControl === iced.FlowControl["IndirectCall"];

export const peApiStringImportSlotRva = (
  iced: IcedX86Module,
  imageBase: bigint,
  instruction: IcedInstructionObject
): number | null => {
  if (!isCallInstruction(iced, instruction) || !isDirectMemoryOperand(iced, instruction, 0)) {
    return null;
  }
  return peApiStringAddressToRva(instruction.memoryDisplacement, imageBase);
};

const normalizeType = (type: string): string =>
  type.toLowerCase().replace(/\s+/gu, " ").trim();

const isConstPointer = (type: string): boolean =>
  /\bconst\b/u.test(type) && type.includes("*");

const hasInputName = (parameter: PeImportMetadataParameter): boolean => {
  const name = parameter.name?.toLowerCase() ?? "";
  return name.includes("name") ||
    name.includes("path") ||
    name.includes("text") ||
    name.includes("caption") ||
    name.includes("file") ||
    name.includes("module") ||
    name.includes("command") ||
    name.includes("format") ||
    name.includes("string") ||
    name.includes("source") ||
    name.includes("mode") ||
    name.includes("delimiter") ||
    name.includes("control") ||
    name.includes("var");
};

const stringEncodingForParameter = (
  parameter: PeImportMetadataParameter
): PeApiStringEncoding | null => {
  if (parameter.direction === "out") return null;
  const type = normalizeType(parameter.type);
  if (type.includes("const wchar_t *")) return "utf-16le";
  if (type.includes("const char *")) return "ascii";
  if (type.endsWith(".pcwstr") || type.endsWith(".lpcwstr")) return "utf-16le";
  if (type.endsWith(".pcstr") || type.endsWith(".lpcstr")) return "ascii";
  if ((type.endsWith(".pwstr") || type.endsWith(".pstr")) && hasInputName(parameter)) {
    return type.endsWith(".pwstr") ? "utf-16le" : "ascii";
  }
  if (isConstPointer(type) && type.includes("wchar_t")) return "utf-16le";
  if (isConstPointer(type) && type.includes("char")) return "ascii";
  return null;
};

const pointerParameterStackSlot = (
  target: PeApiStringImportTarget,
  parameterIndex: number
): number | null => {
  let slot = 0;
  for (let index = 0; index < parameterIndex; index += 1) {
    const bytes = target.metadata.parameters[index]?.x86StackBytes;
    if (bytes == null || bytes % Uint32Array.BYTES_PER_ELEMENT !== 0) return null;
    slot += bytes / Uint32Array.BYTES_PER_ELEMENT;
  }
  return slot;
};

const addressFromInstruction = (
  instruction: PeApiStringRecentInstruction
): PeApiStringAddressSource | null => {
  if (instruction.mnemonic === "Lea" && instruction.memoryAddress != null) {
    return { address: instruction.memoryAddress };
  }
  if (instruction.mnemonic !== "Mov") return null;
  const immediate = instruction.immediateOperands.get(1);
  return immediate == null ? null : { address: immediate };
};

const findRegisterArgument = (
  recent: readonly PeApiStringRecentInstruction[],
  register: string
): PeApiStringAddressSource | null => {
  for (let index = recent.length - 1; index >= 0; index -= 1) {
    const instruction = recent[index];
    if (instruction?.destinationRegister !== register) continue;
    return addressFromInstruction(instruction);
  }
  return null;
};

const pushedAddress = (
  instruction: PeApiStringRecentInstruction
): PeApiStringAddressSource | null => {
  if (instruction.mnemonic !== "Push") return null;
  const immediate = instruction.immediateOperands.get(0);
  return immediate == null ? null : { address: immediate };
};

const collectRecentPushes = (
  recent: readonly PeApiStringRecentInstruction[]
): PeApiStringAddressSource[] => {
  const pushes: PeApiStringAddressSource[] = [];
  for (let index = recent.length - 1; index >= 0; index -= 1) {
    const instruction = recent[index];
    if (!instruction) continue;
    const pushed = pushedAddress(instruction);
    if (pushed) pushes.push(pushed);
  }
  return pushes;
};

const argumentForParameter = (
  bitness: 32 | 64,
  target: PeApiStringImportTarget,
  recent: readonly PeApiStringRecentInstruction[],
  pushes: readonly PeApiStringAddressSource[],
  parameterIndex: number
): PeApiStringAddressSource | null => {
  const register = X64_ARGUMENT_REGISTERS[parameterIndex];
  if (bitness === 64) return register ? findRegisterArgument(recent, register) : null;
  return pushes[pointerParameterStackSlot(target, parameterIndex) ?? -1] ?? null;
};

export const collectPeApiStringCallArguments = (
  bitness: 32 | 64,
  target: PeApiStringImportTarget,
  recent: readonly PeApiStringRecentInstruction[]
): PeApiStringPendingReference[] => {
  const out: PeApiStringPendingReference[] = [];
  const pushes = bitness === 32 ? collectRecentPushes(recent) : [];
  target.metadata.parameters.forEach((parameter, parameterIndex) => {
    const encoding = stringEncodingForParameter(parameter);
    if (encoding == null) return;
    const argument = argumentForParameter(bitness, target, recent, pushes, parameterIndex);
    if (!argument) return;
    out.push({
      address: argument.address,
      encoding,
      callSite: {
        instructionRva: 0,
        module: target.module,
        entrypoint: target.entrypoint,
        sourceKind: target.sourceKind,
        parameterIndex,
        parameterName: parameter.name
      }
    });
  });
  return out;
};
