"use strict";

import type { AnalyzePeInstructionSetOptions } from "../../analyzers/pe/disassembly/types.js";
import { inlinePeSectionName } from "../../analyzers/pe/sections/name.js";
import { createWinapiImportMetadataEntry } from "./pe-import-api-metadata.js";
import { MockFile } from "../helpers/mock-file.js";

export const createPeFlowStopFixture = (bitness: 32 | 64, bytes: number[]) => {
  const imageBase = bitness === 64 ? 0x140000000n : 0x400000n;
  const options: AnalyzePeInstructionSetOptions = {
    coffMachine: bitness === 64 ? 0x8664 : 0x14c, is64Bit: bitness === 64,
    imageBase, entrypointRva: 0x1000,
    sections: [{ name: inlinePeSectionName(".text"), virtualAddress: 0x1000,
      virtualSize: bytes.length, sizeOfRawData: bytes.length, pointerToRawData: 0,
      characteristics: 0x60000020 }],
    rvaToOff: rva => rva >= 0x1000 && rva < 0x1000 + bytes.length ? rva - 0x1000 : null,
    imports: { thunkEntrySize: bitness === 64 ? 8 : 4, entries: [{
      dll: "kernel32.dll", originalFirstThunkRva: 0x3000, firstThunkRva: 0x2000,
      timeDateStamp: 0, forwarderChain: 0, lookupSource: "import-lookup-table",
      thunkTableTerminated: true, functions: [{ name: "ExitProcess",
        apiMetadata: { ...createWinapiImportMetadataEntry("kernel32.dll", "ExitProcess"),
          noReturn: true } }]
    }] }
  };
  return { file: new MockFile(new Uint8Array(bytes)), options };
};

export const directIatCall = (bitness: 32 | 64, instructionRva = 0x1000): number[] => {
  // Intel SDM: FF /2 with RIP-relative disp32 on x64 or absolute disp32 on x86.
  const operand = bitness === 64 ? 0x2000 - instructionRva - 6 : 0x402000;
  const bytes = new Uint8Array(6);
  bytes.set([0xff, 0x15]);
  new DataView(bytes.buffer).setInt32(2, operand, true);
  return [...bytes];
};

export const createPeImportThunkFixture = (bitness: 32 | 64) => {
  // CALL rel32 at 0x1000 targets the import JMP thunk at 0x1010.
  const bytes = new Array<number>(22).fill(0x90);
  bytes.splice(0, 9, 0xe8, 11, 0, 0, 0, 0x0f, 0x28, 0xc0, 0xc3);
  const jump = directIatCall(bitness, 0x1010);
  jump[1] = 0x25; // Intel SDM: FF /4 is an indirect near JMP.
  bytes.splice(16, 6, ...jump);
  return createPeFlowStopFixture(bitness, bytes);
};

export const setPeFlowStopMetadata = (
  options: AnalyzePeInstructionSetOptions,
  metadata: "returning" | "missing" | "legacy" | "overlap" | "invalid-slot"
): void => {
  const entry = options.imports!.entries[0]!;
  const imported = entry.functions[0]!;
  if (metadata === "legacy") imported.winapiMetadata = { ...imported.apiMetadata!, sourceKind: "winapi" };
  if (metadata === "legacy" || metadata === "missing") delete imported.apiMetadata;
  if (metadata === "returning") imported.apiMetadata!.noReturn = false;
  if (metadata === "invalid-slot") entry.firstThunkRva += 0x1_0000_0000;
  if (metadata === "overlap") options.imports!.entries.push({ ...entry,
    functions: [{ name: "ReturningAlias" }] });
};
