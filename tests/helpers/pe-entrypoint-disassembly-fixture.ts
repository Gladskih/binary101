"use strict";

import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import { analyzePeEntrypointDisassembly } from "../../analyzers/pe/disassembly/index.js";
import type { AnalyzePeEntrypointDisassemblyOptions } from "../../analyzers/pe/disassembly/index.js";
import {
  IMAGE_FILE_MACHINE_AMD64,
  IMAGE_FILE_MACHINE_I386
} from "../../analyzers/coff/machine.js";
import { inlinePeSectionName } from "../../analyzers/pe/sections/name.js";
import type { PeSection } from "../../analyzers/pe/types.js";
import { MockFile } from "./mock-file.js";

// Microsoft PE format: section flags used by synthetic PE fixtures.
export { IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386 };
export const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
export const IMAGE_SCN_CNT_CODE = 0x00000020;
export const testDecoderBitnesses: number[] = [];

export class TestInstruction {
  code = 1;
  length = 0;
  ip = 0n;
  nextIP = 0n;
  mnemonic = 0;
  flowControl = 0;
  opCount = 0;
  nearBranchTarget = 0n;
  memoryBase = 0;
  memoryDisplacement = 0n;
  memoryIndex = 0;
  memoryIndexScale = 1;
  op0Kind = 0;
  isCallNearIndirect = false;
  isIpRelMemoryOperand = false;
  isJmpNearIndirect = false;
  ipRelMemoryAddress = 0n;
  text = "";
  opKind(): number {
    return 0;
  }
  opRegister(): number {
    return 0;
  }
  immediate(): bigint {
    return 0n;
  }
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
    instruction.mnemonic = 0;
    instruction.flowControl = 0;
    instruction.nearBranchTarget = 0n;
    instruction.memoryBase = 0;
    instruction.memoryDisplacement = 0n;
    instruction.memoryIndex = 0;
    instruction.memoryIndexScale = 1;
    instruction.op0Kind = 0;
    instruction.isCallNearIndirect = false;
    instruction.isIpRelMemoryOperand = false;
    instruction.isJmpNearIndirect = false;
    instruction.ipRelMemoryAddress = 0n;
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
      instruction.isCallNearIndirect = true;
      instruction.isIpRelMemoryOperand = true;
      instruction.memoryDisplacement = 0x140002000n;
      instruction.ipRelMemoryAddress = 0x140002000n;
      instruction.op0Kind = 24;
      instruction.text = "call [iat]";
    } else if (byte === 0x25) {
      instruction.flowControl = 2;
      instruction.isIpRelMemoryOperand = true;
      instruction.isJmpNearIndirect = true;
      instruction.memoryDisplacement = 0x140002000n;
      instruction.ipRelMemoryAddress = 0x140002000n;
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
  Mnemonic: {
    Add: 7,
    And: 21,
    Bt: 54,
    Cpuid: 106,
    Lea: 368,
    Mov: 414,
    Or: 486,
    Pop: 534,
    Push: 586,
    Sub: 703,
    Test: 751,
    Xor: 1518
  },
  OpKind: {
    Register: 0,
    NearBranch16: 1,
    NearBranch32: 2,
    NearBranch64: 3,
    Immediate8: 10,
    Immediate8_2nd: 11,
    Immediate16: 12,
    Immediate32: 13,
    Immediate64: 14,
    Immediate8to16: 15,
    Immediate8to32: 16,
    Immediate8to64: 17,
    Immediate32to64: 18,
    Memory: 24
  },
  Register: {
    EAX: 37,
    ECX: 38,
    EDX: 39,
    EBX: 40,
    ESP: 44,
    RAX: 53,
    RCX: 54,
    RDX: 55,
    RBX: 56,
    RSP: 60
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
