"use strict";

import type * as IcedPackage from "iced-x86-disasm";

/** Fields consumed by analyzers, with their types taken from the installed package. */
export type IcedInstructionObject = Pick<IcedPackage.Instruction,
  "code" | "length" | "ip" | "nextIP" | "mnemonic" | "flowControl" | "opCount" |
  "nearBranchTarget" | "memoryBase" | "memoryDisplacement" | "memoryIndex" |
  "memoryIndexScale" | "memorySize" | "op0Kind" | "hasRepPrefix" |
  "hasRepePrefix" | "hasRepnePrefix" | "isCallNearIndirect" |
  "isIpRelMemoryOperand" | "isJmpNearIndirect" | "ipRelMemoryAddress" |
  "opKind" | "opRegister" | "immediate" | "cpuidFeatures" | "free"
> & Partial<Pick<IcedPackage.Instruction, "isPrivileged">>;

export type IcedX86Module = Pick<typeof IcedPackage,
  "Code" | "CpuidFeature" | "Decoder" | "DecoderOptions" | "FlowControl" |
  "OpKind" | "Instruction"
> & Partial<Pick<typeof IcedPackage,
  "InstructionInfoFactory" | "Mnemonic" | "MemorySize" | "OpAccess" | "Register"
>>;

export const lookupIcedEnumValue = (table: object | undefined, name: string): number | undefined => {
  if (!table) return undefined;
  try {
    const value: unknown = Reflect.get(table, name);
    return typeof value === "number" ? value : undefined;
  } catch {
    return undefined;
  }
};

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null;

export const isIcedX86Module = (value: unknown): value is IcedX86Module => {
  if (!isRecord(value)) return false;

  const decoderOptions = value["DecoderOptions"];
  if (!isRecord(decoderOptions) || typeof decoderOptions["None"] !== "number") return false;

  const code = value["Code"];
  if (!isRecord(code) || typeof code["INVALID"] !== "number") return false;

  const cpuidFeature = value["CpuidFeature"];
  const flowControl = value["FlowControl"];
  const opKind = value["OpKind"];
  if (!isRecord(cpuidFeature) || !isRecord(flowControl) || !isRecord(opKind)) return false;

  return typeof value["Decoder"] === "function" && typeof value["Instruction"] === "function";
};
