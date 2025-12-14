"use strict";

type IcedInstruction = {
  code: number;
  length: number;
  ip: bigint;
  nextIP: bigint;
  readonly flowControl: number;
  readonly nearBranchTarget: bigint;
  op0Kind: number;
  cpuidFeatures(): Int32Array;
  free(): void;
};

type IcedDecoder = {
  ip: bigint;
  canDecode: boolean;
  position: number;
  decodeOut(instruction: IcedInstruction): void;
  free(): void;
};

export type IcedX86Module = {
  Code: Record<string, number> & Record<number, string | undefined>;
  CpuidFeature: Record<string, number> & Record<number, string | undefined>;
  Decoder: new (bitness: number, data: Uint8Array, options: number) => IcedDecoder;
  DecoderOptions: { None: number };
  FlowControl: Record<string, number> & Record<number, string | undefined>;
  OpKind: Record<string, number> & Record<number, string | undefined>;
  Instruction: new () => IcedInstruction;
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

