"use strict";

/**
 * Runtime `iced-x86` instruction object shape consumed by Binary101 analyzers.
 *
 * This is an adapter type for the JS/WASM API, not Binary101's own immutable
 * instruction model. iced-x86 decodes into a reusable `Instruction` object via
 * `Decoder.decodeOut()` and exposes operands through accessor methods, so this
 * type mirrors that object API. Analyzer code treats decoded fields as read-only.
 */
export type IcedInstructionObject = {
  readonly code: number;
  readonly length: number;
  readonly ip: bigint;
  readonly nextIP: bigint;
  readonly mnemonic: number;
  readonly flowControl: number;
  readonly opCount: number;
  readonly nearBranchTarget: bigint;
  readonly memoryBase: number;
  readonly memoryDisplacement: bigint;
  readonly memoryIndex: number;
  readonly memoryIndexScale: number;
  readonly memorySize: number;
  readonly op0Kind: number;
  readonly isCallNearIndirect: boolean;
  readonly isIpRelMemoryOperand: boolean;
  readonly isJmpNearIndirect: boolean;
  readonly ipRelMemoryAddress: bigint;
  opKind(operand: number): number;
  opRegister(operand: number): number;
  immediate(operand: number): bigint;
  cpuidFeatures(): Int32Array;
  free(): void;
};

type IcedInstructionInfo = {
  readonly op0Access: number;
  free(): void;
};

type IcedInstructionInfoFactory = {
  info(instruction: IcedInstructionObject): IcedInstructionInfo;
  free(): void;
};

type IcedDecoder = {
  ip: bigint;
  canDecode: boolean;
  position: number;
  decodeOut(instruction: IcedInstructionObject): void;
  free(): void;
};

export type IcedX86Module = {
  Code: Record<string, number> & Record<number, string | undefined>;
  CpuidFeature: Record<string, number> & Record<number, string | undefined>;
  Decoder: new (bitness: number, data: Uint8Array<ArrayBufferLike>, options: number) => IcedDecoder;
  DecoderOptions: { None: number };
  FlowControl: Record<string, number> & Record<number, string | undefined>;
  InstructionInfoFactory?: new () => IcedInstructionInfoFactory;
  Mnemonic?: Record<string, number> & Record<number, string | undefined>;
  MemorySize?: Record<string, number> & Record<number, string | undefined>;
  OpAccess?: Record<string, number> & Record<number, string | undefined>;
  OpKind: Record<string, number> & Record<number, string | undefined>;
  Register?: Record<string, number> & Record<number, string | undefined>;
  Instruction: new () => IcedInstructionObject;
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
