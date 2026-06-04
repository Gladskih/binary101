"use strict";

import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import { analyzePeEntrypointDisassembly } from "../../analyzers/pe/disassembly/index.js";
import type { AnalyzePeEntrypointDisassemblyOptions } from "../../analyzers/pe/disassembly/index.js";
import { inlinePeSectionName } from "../../analyzers/pe/sections/name.js";
import type { PeSection } from "../../analyzers/pe/types.js";
import { MockFile } from "./mock-file.js";

// Microsoft PE format: machine types and section flags used by synthetic PE fixtures.
export const IMAGE_FILE_MACHINE_I386 = 0x014c;
export const IMAGE_FILE_MACHINE_AMD64 = 0x8664;
export const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
export const IMAGE_SCN_CNT_CODE = 0x00000020;
export const testDecoderBitnesses: number[] = [];

export class TestInstruction {
  code = 1;
  length = 0;
  ip = 0n;
  nextIP = 0n;
  flowControl = 0;
  nearBranchTarget = 0n;
  memoryDisplacement = 0n;
  op0Kind = 0;
  text = "";
  free(): void {}
}

export class TestDecoder {
  ip = 0n;
  position = 0;
  constructor(
    bitness: number,
    readonly data: Uint8Array
  ) {
    testDecoderBitnesses.push(bitness);
  }
  get canDecode(): boolean {
    return this.position < this.data.length;
  }
  decodeOut(instruction: TestInstruction): void {
    const byte = this.data[this.position] ?? 0xff;
    instruction.ip = this.ip;
    instruction.length = 1;
    instruction.nextIP = this.ip + 1n;
    instruction.code = byte === 0xff ? 0 : 1;
    instruction.flowControl = 0;
    instruction.nearBranchTarget = 0n;
    instruction.memoryDisplacement = 0n;
    instruction.op0Kind = 0;
    instruction.text = byte === 0xff ? "invalid" : `op_${byte.toString(16)}`;
    if (byte === 0xc3) {
      instruction.flowControl = 4;
      instruction.text = "ret";
    } else if (byte === 0xe8) {
      instruction.flowControl = 5;
      instruction.nearBranchTarget = this.ip + 2n;
      instruction.op0Kind = 2;
      instruction.text = "call near";
    } else if (byte === 0xe9) {
      instruction.flowControl = 1;
      instruction.nearBranchTarget = this.ip + 2n;
      instruction.op0Kind = 2;
      instruction.text = "jmp near";
    } else if (byte === 0x74) {
      instruction.flowControl = 3;
      instruction.nearBranchTarget = this.ip + 2n;
      instruction.op0Kind = 2;
      instruction.text = "je short";
    } else if (byte === 0x15) {
      instruction.flowControl = 6;
      instruction.memoryDisplacement = 0x140002000n;
      instruction.op0Kind = 24;
      instruction.text = "call [iat]";
    } else if (byte === 0x25) {
      instruction.flowControl = 2;
      instruction.memoryDisplacement = 0x140002000n;
      instruction.op0Kind = 24;
      instruction.text = "jmp [iat]";
    }
    this.position += 1;
    this.ip = instruction.nextIP;
  }
  free(): void {}
}

export const fakeIced = {
  Code: { INVALID: 0 },
  CpuidFeature: {},
  Decoder: TestDecoder,
  DecoderOptions: { None: 0 },
  FlowControl: {
    Next: 0,
    UnconditionalBranch: 1,
    IndirectBranch: 2,
    ConditionalBranch: 3,
    Return: 4,
    Call: 5,
    IndirectCall: 6
  },
  Formatter: class {
    format(instruction: TestInstruction): string {
      return instruction.text;
    }
    free(): void {}
  },
  FormatterSyntax: { Nasm: 0 },
  Instruction: TestInstruction,
  OpKind: {
    NearBranch16: 1,
    NearBranch32: 2,
    NearBranch64: 3,
    Memory: 24
  }
};

export const throwingFreeIced = {
  ...fakeIced,
  Decoder: class extends TestDecoder {
    override free(): void {
      throw new Error("decoder free");
    }
  },
  Formatter: class {
    format(instruction: TestInstruction): string {
      return instruction.text;
    }
    free(): void {
      throw new Error("formatter free");
    }
  },
  Instruction: class extends TestInstruction {
    override free(): void {
      throw new Error("instruction free");
    }
  }
};

export const createExecutableSection = (overrides: Partial<PeSection> = {}): PeSection => ({
  name: inlinePeSectionName(".text"),
  virtualSize: 4,
  virtualAddress: 0x1000,
  sizeOfRawData: 4,
  pointerToRawData: 0,
  characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE,
  ...overrides
});

export const analyzeEntrypoint = (
  bytes: Uint8Array,
  section: PeSection = createExecutableSection(),
  entrypointRva = 0x1000,
  overrides: Partial<AnalyzePeEntrypointDisassemblyOptions> = {}
): ReturnType<typeof analyzePeEntrypointDisassembly> =>
  analyzePeEntrypointDisassembly(
    createFileRangeReader(new MockFile(bytes, "entry.exe"), 0, bytes.length),
    {
      coffMachine: IMAGE_FILE_MACHINE_AMD64,
      is64Bit: true,
      imageBase: 0x140000000n,
      entrypointRva,
      headerRvaLimit: 0x400,
      rvaToOff: rva => rva - 0x1000,
      sections: [section],
      ...overrides
    },
    async () => fakeIced
  );
