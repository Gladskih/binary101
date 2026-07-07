"use strict";

import type { PeEntrypointInstruction } from "../../analyzers/pe/disassembly/index.js";
import {
  createEmulationState,
  emulateInstruction,
  type EmulationState
} from "../../analyzers/pe/disassembly/entrypoint/emulation/index.js";
import type {
  IcedFormatter,
  IcedInstructionObject,
  IcedModule
} from "../../analyzers/pe/disassembly/entrypoint/iced.js";

type EnumMap<T extends string> = Record<T, number> & Record<number, string | undefined>;

const createEnumMap = <T extends string>(names: readonly T[]): EnumMap<T> => {
  const map: Record<string | number, string | number | undefined> = {};
  names.forEach((name, index) => {
    const value = index + 1;
    map[name] = value;
    map[value] = name;
  });
  return map as EnumMap<T>;
};

const mnemonicNames = [
  "Adc", "Add", "And", "Bsf", "Bsr", "Bswap", "Bt", "Btc", "Btr", "Bts",
  "Cbw", "Cdq", "Cdqe", "Clc", "Cld", "Cmc", "Cmp", "Cmpxchg", "Cpuid", "Cqo",
  "Crc32", "Cwd", "Cwde", "Dec", "Div", "Enter", "Idiv", "Imul", "Inc",
  "Lahf", "Lea", "Leave", "Lodsb", "Lodsd", "Lodsq", "Lodsw", "Lzcnt",
  "Mov", "Movbe", "Movsb", "Movsd", "Movsq", "Movsw", "Movsx", "Movsxd",
  "Movzx", "Mul", "Neg", "Not", "Or", "Pop", "Popa", "Popad", "Popcnt",
  "Popf", "Popfd", "Popfq", "Push", "Pusha", "Pushad", "Pushf", "Pushfd",
  "Pushfq", "Rcl", "Rcr", "Rol", "Ror", "Sahf", "Sal", "Sar", "Sbb",
  "Sete", "Setne", "Shl", "Shld", "Shr", "Shrd", "Stc", "Sub", "Test",
  "Tzcnt", "Xadd", "Xchg", "Xor", "Cmove", "Cmovne", "Ja", "Jae", "Jb",
  "Jbe", "Je", "Jg", "Jge", "Jl", "Jle", "Jne", "Jno", "Jnp", "Jns",
  "Jo", "Jp", "Js", "Jcxz", "Jecxz", "Jrcxz", "Jmp", "Loop", "Loope",
  "Loopne", "Call", "Ret", "Retf", "Std", "Stosb", "Stosd", "Stosq", "Stosw"
] as const;

const registerNames = [
  "None", "RAX", "EAX", "AX", "AL", "AH", "RBX", "EBX", "BX", "BL", "BH",
  "RCX", "ECX", "CX", "CL", "CH", "RDX", "EDX", "DX", "DL", "DH", "RSI",
  "ESI", "SI", "SIL", "RDI", "EDI", "DI", "DIL", "RBP", "EBP", "BP",
  "BPL", "RSP", "ESP", "SP", "SPL", "R8", "R8D", "R8W", "R8L", "R9",
  "R9D", "R9W", "R9L", "R10", "R10D", "R10W", "R10L", "R11", "R11D",
  "R11W", "R11L", "R12", "R12D", "R12W", "R12L", "R13", "R13D", "R13W",
  "R13L", "R14", "R14D", "R14W", "R14L", "R15", "R15D", "R15W", "R15L",
  "RIP", "EIP", "XMM0"
] as const;

const opKindNames = [
  "Register", "NearBranch16", "NearBranch32", "NearBranch64", "Immediate8",
  "Immediate8_2nd", "Immediate16", "Immediate32", "Immediate64",
  "Immediate8to16", "Immediate8to32", "Immediate8to64", "Immediate32to64",
  "MemorySegSI", "MemorySegESI", "MemorySegRSI", "MemorySegDI", "MemorySegEDI",
  "MemorySegRDI", "MemoryESDI", "MemoryESEDI", "MemoryESRDI", "Memory"
] as const;

const memorySizeNames = [
  "UInt8", "Int8", "UInt16", "Int16", "UInt32", "Int32", "UInt64", "Int64"
] as const;

const codeNames = [
  "INVALID", "Valid", "Enterw", "Enterd", "Enterq", "Leavew", "Leaved", "Leaveq",
  "Push_r16", "Push_r32", "Push_r64", "Pop_r16", "Pop_r32", "Pop_r64",
  "Loop_rel8_16_CX", "Loop_rel8_32_ECX", "Loop_rel8_64_RCX",
  "Loope_rel8_16_CX", "Loope_rel8_32_ECX", "Loope_rel8_64_RCX",
  "Loopne_rel8_16_CX", "Loopne_rel8_32_ECX", "Loopne_rel8_64_RCX",
  "Pushd_imm8", "Pushd_imm32",
  "Retnw", "Retnw_imm16", "Retnd", "Retnd_imm16", "Retnq", "Retnq_imm16",
  "Retfw", "Retfw_imm16", "Retfd", "Retfd_imm16", "Retfq", "Retfq_imm16"
] as const;

const flowControlNames = [
  "Next", "UnconditionalBranch", "IndirectBranch", "ConditionalBranch",
  "Return", "Call", "IndirectCall"
] as const;

export type FixtureMnemonic = (typeof mnemonicNames)[number];
export type FixtureRegister = (typeof registerNames)[number];
export type FixtureCode = (typeof codeNames)[number];
export type FixtureMemorySize = (typeof memorySizeNames)[number];
export type FixtureOpKind = (typeof opKindNames)[number];
export type FixtureFlowControl = (typeof flowControlNames)[number];

type FixtureOperand =
  | { kind: "register"; register: FixtureRegister }
  | { kind: "immediate"; value: bigint; opKind: FixtureOpKind }
  | { kind: "implicit-memory"; opKind: FixtureOpKind; size: FixtureMemorySize }
  | {
      kind: "memory";
      base?: FixtureRegister;
      index?: FixtureRegister;
      scale?: number;
      displacement?: bigint;
      size: FixtureMemorySize;
    };

type FixtureInstructionSpec = {
  indirectControlFlow?: "near-call" | "near-jump" | "far-call";
  code?: FixtureCode; flowControl?: FixtureFlowControl; ip?: bigint; length?: number;
  nearBranchTarget?: bigint; repeatPrefix?: "rep" | "repe" | "repne";
};

const fixtureCode = createEnumMap(codeNames);
const fixtureFlowControl = createEnumMap(flowControlNames);
const fixtureMemorySize = createEnumMap(memorySizeNames);
const fixtureMnemonic = createEnumMap(mnemonicNames);
const fixtureOpKind = createEnumMap(opKindNames);
const fixtureRegister = createEnumMap(registerNames);

class FixtureFormatter implements IcedFormatter {
  format(instruction: IcedInstructionObject): string {
    return fixtureMnemonic[instruction.mnemonic] ?? "fixture";
  }
  free(): void {}
}

class FixtureInstruction implements IcedInstructionObject {
  readonly code: number; readonly flowControl: number; readonly length: number;
  readonly hasRepPrefix: boolean; readonly hasRepePrefix: boolean;
  readonly hasRepnePrefix: boolean; readonly memoryBase: number;
  readonly memoryDisplacement: bigint; readonly memoryIndex: number;
  readonly memoryIndexScale: number; readonly memorySize: number; readonly mnemonic: number;
  readonly nearBranchTarget: bigint; readonly nextIP: bigint; readonly op0Kind: number;
  readonly opCount: number; readonly ip: bigint; readonly isCallNearIndirect: boolean;
  readonly isIpRelMemoryOperand: boolean; readonly isJmpNearIndirect: boolean;
  readonly ipRelMemoryAddress: bigint;
  constructor(
    mnemonic: FixtureMnemonic,
    private readonly operands: readonly FixtureOperand[],
    spec: FixtureInstructionSpec
  ) {
    const memory = operands.find(operand => operand.kind === "memory");
    this.code = fixtureCode[spec.code ?? "Valid"] ?? 0;
    this.flowControl = fixtureFlowControl[spec.flowControl ?? "Next"] ?? 0;
    this.hasRepPrefix = spec.repeatPrefix === "rep" || spec.repeatPrefix === "repe";
    this.hasRepePrefix = this.hasRepPrefix;
    this.hasRepnePrefix = spec.repeatPrefix === "repne";
    this.ip = spec.ip ?? 0n;
    this.length = spec.length ?? 1;
    this.memoryBase = memory?.kind === "memory"
      ? fixtureRegister[memory.base ?? "None"] ?? 0
      : fixtureRegister["None"] ?? 0;
    this.memoryDisplacement = memory?.kind === "memory" ? memory.displacement ?? 0n : 0n;
    this.memoryIndex = memory?.kind === "memory"
      ? fixtureRegister[memory.index ?? "None"] ?? 0
      : fixtureRegister["None"] ?? 0;
    this.memoryIndexScale = memory?.kind === "memory" ? memory.scale ?? 1 : 1;
    const sizedMemory = operands.find(operand =>
      operand.kind === "memory" || operand.kind === "implicit-memory"
    );
    this.memorySize = sizedMemory?.kind === "memory" || sizedMemory?.kind === "implicit-memory"
      ? fixtureMemorySize[sizedMemory.size] ?? 0
      : 0;
    this.mnemonic = fixtureMnemonic[mnemonic] ?? 0;
    this.nearBranchTarget = spec.nearBranchTarget ?? 0n;
    this.nextIP = this.ip + BigInt(this.length);
    this.op0Kind = this.opKind(0);
    this.opCount = operands.length;
    const inferredIndirectControlFlow =
      spec.flowControl === "IndirectCall" && this.op0Kind === fixtureOpKind["Memory"]
        ? "near-call"
        : spec.flowControl === "IndirectBranch" && this.op0Kind === fixtureOpKind["Memory"]
          ? "near-jump"
          : null;
    const indirectControlFlow = spec.indirectControlFlow ?? inferredIndirectControlFlow;
    this.isCallNearIndirect = indirectControlFlow === "near-call";
    this.isIpRelMemoryOperand =
      this.memoryBase === fixtureRegister["RIP"] || this.memoryBase === fixtureRegister["EIP"];
    this.isJmpNearIndirect = indirectControlFlow === "near-jump";
    this.ipRelMemoryAddress = this.isIpRelMemoryOperand
      ? this.memoryDisplacement
      : 0n;
  }
  opKind(operand: number): number {
    const data = this.operands[operand];
    if (!data) return 0;
    if (data.kind === "register") return fixtureOpKind["Register"] ?? 0;
    if (data.kind === "memory") return fixtureOpKind["Memory"] ?? 0;
    if (data.kind === "implicit-memory") return fixtureOpKind[data.opKind] ?? 0;
    return fixtureOpKind[data.opKind] ?? 0;
  }
  opRegister(operand: number): number {
    const data = this.operands[operand];
    return data?.kind === "register" ? fixtureRegister[data.register] ?? 0 : 0;
  }
  immediate(operand: number): bigint {
    const data = this.operands[operand];
    if (data?.kind !== "immediate") throw new Error("fixture operand is not immediate");
    return data.value;
  }
  cpuidFeatures(): Int32Array {
    return new Int32Array();
  }
  free(): void {}
}

class FixtureDecoder {
  ip = 0n;
  position = 0;
  constructor(
    _bitness: number,
    readonly data: Uint8Array
  ) {}
  get canDecode(): boolean {
    return this.position < this.data.length;
  }
  decodeOut(instruction: IcedInstructionObject): void {
    Object.assign(instruction, new FixtureInstruction("Cpuid", [], {
      ip: this.ip,
      length: Math.min(1, this.data.length - this.position)
    }));
    this.position += instruction.length;
    this.ip = instruction.nextIP;
  }
  free(): void {}
}

class EmptyFixtureInstruction extends FixtureInstruction {
  constructor() {
    super("Cpuid", [], {});
  }
}

export const fixtureIced = {
  Code: fixtureCode,
  CpuidFeature: {},
  Decoder: FixtureDecoder,
  DecoderOptions: { None: 0 },
  FlowControl: fixtureFlowControl,
  Formatter: FixtureFormatter,
  FormatterSyntax: { Nasm: 0 },
  Instruction: EmptyFixtureInstruction,
  MemorySize: fixtureMemorySize,
  Mnemonic: fixtureMnemonic,
  OpKind: fixtureOpKind,
  Register: fixtureRegister
} as unknown as IcedModule;

export const reg = (register: FixtureRegister): FixtureOperand => ({ kind: "register", register });

export const imm = (
  value: number | bigint,
  opKind: FixtureOpKind = "Immediate32"
): FixtureOperand => ({
  kind: "immediate",
  opKind,
  value: BigInt(value)
});

export const mem = (
  size: FixtureMemorySize,
  base?: FixtureRegister,
  displacement = 0n,
  index?: FixtureRegister,
  scale = 1
): FixtureOperand => {
  const operand: Extract<FixtureOperand, { kind: "memory" }> = {
    kind: "memory",
    displacement,
    scale,
    size
  };
  if (base != null) operand.base = base;
  if (index != null) operand.index = index;
  return operand;
};

export const implicitMem = (
  opKind: Extract<FixtureOpKind, `Memory${string}`>,
  size: FixtureMemorySize
): FixtureOperand =>
  ({ kind: "implicit-memory", opKind, size });

export const instruction = (
  mnemonic: FixtureMnemonic,
  operands: readonly FixtureOperand[] = [],
  spec: FixtureInstructionSpec = {}
): IcedInstructionObject => new FixtureInstruction(mnemonic, operands, spec);

export const emulateFixtures = (
  instructions: readonly IcedInstructionObject[],
  bitness: 32 | 64 = 64
): { rendered: PeEntrypointInstruction[]; state: EmulationState } => {
  const state = createEmulationState(bitness);
  const rendered = instructions.map((decoded, index) => {
    const item = { rva: index, fileOffset: index, text: "" };
    emulateInstruction(fixtureIced, decoded, item, state);
    return item;
  });
  return { rendered, state };
};
