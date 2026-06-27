"use strict";

import type { FileRangeReader } from "../../file-range-reader.js";
import type { IcedInstructionObject } from "../../x86/disassembly-iced.js";
import type { PeImportMetadataEntry } from "../../../pe-import-metadata-schema.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../layout/rva-limits.js";
import type {
  PeApiStringCallSite,
  PeApiStringEncoding,
  PeApiStringReference
} from "./types.js";

export type PeApiStringImportTarget = {
  module: string;
  entrypoint: string;
  sourceKind: PeImportMetadataEntry["sourceKind"];
  metadata: PeImportMetadataEntry;
};

export type PeApiStringAddressSource = {
  address: bigint;
};

export type PeApiStringAddressCandidate = {
  address: bigint;
  encoding: PeApiStringEncoding;
};

export type PeApiStringRecentInstruction = {
  ip: bigint;
  nextIp: bigint;
  mnemonic: string | undefined;
  destinationRegister: string | undefined;
  immediateOperands: Map<number, bigint>;
  memoryAddress: bigint | null;
};

export type PeApiStringPendingReference = PeApiStringAddressCandidate & {
  callSite: PeApiStringCallSite;
};

export type PeApiStringDecoded = {
  rva: number;
  encoding: PeApiStringEncoding;
  byteLength: number;
  text: string;
};

export type PeApiStringReferenceCollector = {
  record(instruction: IcedInstructionObject): void;
  references(reader: FileRangeReader): Promise<PeApiStringReference[]>;
};

export const peApiStringAddressToRva = (
  address: bigint,
  imageBase: bigint
): number | null => {
  const rva = address >= imageBase ? address - imageBase : address;
  if (rva < 0n || rva >= BigInt(PE_RVA_EXCLUSIVE_LIMIT)) return null;
  const value = Number(rva);
  return Number.isSafeInteger(value) ? value >>> 0 : null;
};
