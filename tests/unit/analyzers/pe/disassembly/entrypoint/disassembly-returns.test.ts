"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86";
import { createFileRangeReader } from "../../../../../../analyzers/file-range-reader.js";
import {
  analyzePeEntrypointDisassembly,
  type PeEntrypointInstructionTarget
} from "../../../../../../analyzers/pe/disassembly/index.js";
import type {
  IcedInstructionObject
} from "../../../../../../analyzers/pe/disassembly/entrypoint/iced.js";
import { MockFile } from "../../../../../helpers/mock-file.js";
import {
  IMAGE_FILE_MACHINE_I386,
  createExecutableSection
} from "../../../../../helpers/pe-entrypoint-disassembly-fixture.js";
import {
  imm,
  instruction as ins
} from "../../../../../helpers/pe-entrypoint-emulation-fixture.js";
import { createScriptedIced } from "../../../../../helpers/pe-entrypoint-scripted-iced-fixture.js";

const assertKnownReturnTarget = (
  target: PeEntrypointInstructionTarget | undefined
): Extract<PeEntrypointInstructionTarget, { kind: "return"; rva: number }> => {
  assert.equal(target?.kind, "return");
  assert.ok(target && "rva" in target);
  return target;
};

const analyzeRealEntrypoint = (bytes: Uint8Array) => {
  const section = createExecutableSection({
    sizeOfRawData: bytes.length,
    virtualSize: bytes.length
  });
  return analyzePeEntrypointDisassembly(
    createFileRangeReader(new MockFile(bytes, "entry.exe"), 0, bytes.length),
    {
      coffMachine: IMAGE_FILE_MACHINE_I386,
      is64Bit: false,
      imageBase: 0n, // Keep fixture virtual addresses equal to RVAs.
      entrypointRva: section.virtualAddress,
      rvaToOff: rva => rva - section.virtualAddress,
      sections: [section]
    },
    async () => iced
  );
};

const scriptedByteLength = (
  instructions: Parameters<typeof createScriptedIced>[0]
): number => {
  const startIp = instructions[0]?.ip ?? 0n;
  return Math.max(...instructions.map(instruction => Number(instruction.nextIP - startIp)));
};

const analyzeScriptedEntrypoint = (
  instructions: Parameters<typeof createScriptedIced>[0]
): ReturnType<typeof analyzePeEntrypointDisassembly> => {
  const byteLength = scriptedByteLength(instructions);
  const section = createExecutableSection({
    sizeOfRawData: byteLength,
    virtualAddress: Number(instructions[0]?.ip ?? 0n),
    virtualSize: byteLength
  });
  return analyzePeEntrypointDisassembly(
    createFileRangeReader(
      new MockFile(new Uint8Array(byteLength), "scripted-entry.exe"),
      0,
      byteLength
    ),
    {
      coffMachine: IMAGE_FILE_MACHINE_I386,
      is64Bit: false,
      imageBase: 0n, // Keep scripted instruction ips equal to RVAs.
      entrypointRva: section.virtualAddress,
      rvaToOff: rva => rva - section.virtualAddress,
      sections: [section]
    },
    async () => createScriptedIced(instructions)
  );
};

const scriptedInstructionLength = (): number => Uint8Array.BYTES_PER_ELEMENT;

const createFarReturnReleasedArgumentScenario = (): {
  instructions: IcedInstructionObject[];
  returnSiteRva: number;
} => {
  const instructions: IcedInstructionObject[] = [];
  let nextRva = createExecutableSection().virtualAddress;
  const append = (
    mnemonic: Parameters<typeof ins>[0],
    operands: Parameters<typeof ins>[1],
    spec: Parameters<typeof ins>[2]
  ): number => {
    const rva = nextRva;
    instructions.push(ins(mnemonic, operands, {
      ...spec,
      ip: BigInt(rva),
      length: scriptedInstructionLength()
    }));
    nextRva += scriptedInstructionLength();
    return rva;
  };
  const pushDword = (value: bigint): void => {
    append("Push", [imm(value, "Immediate32")], { code: "Pushd_imm32" });
  };
  const callNear = (targetRva: number): void => {
    append("Call", [imm(BigInt(targetRva), "NearBranch32")], {
      flowControl: "Call",
      nearBranchTarget: BigInt(targetRva)
    });
  };
  const retNear = (): number => append("Ret", [], {
    code: "Retnd",
    flowControl: "Return"
  });
  const retFarReleasingDwords = (releasedDwords: number): void => {
    append("Retf", [imm(Uint32Array.BYTES_PER_ELEMENT * releasedDwords, "Immediate16")], {
      code: "Retfd_imm16",
      flowControl: "Return"
    });
  };
  const entrypointRva = nextRva;
  // Reuse an executable RVA so stale stack cleanup would expose a plausible return target.
  const releasedArguments = [BigInt(entrypointRva), BigInt(entrypointRva)];
  for (const value of releasedArguments) pushDword(value);
  pushDword(BigInt(entrypointRva));
  const returnSiteRva = nextRva + scriptedInstructionLength();
  const farReturnRva = returnSiteRva + scriptedInstructionLength();
  callNear(farReturnRva);
  retNear();
  retFarReleasingDwords(releasedArguments.length);
  return { instructions, returnSiteRva };
};

void test(
  "analyzePeEntrypointDisassembly follows a return address changed on the stack",
  async () => {
    const bytes = new Uint8Array([
      0xe8, 0x02, 0x00, 0x00, 0x00,
      0x90,
      0xcc,
      0xc7, 0x04, 0x24, 0x0f, 0x10, 0x00, 0x00,
      0xc3,
      0xc3
    ]);
    const result = await analyzeRealEntrypoint(bytes);
    const returnTarget = result.blocks[1]?.instructions.at(-1)?.target;

    assert.equal(result.blocks.length, 3);
    assert.equal(result.blocks[1]?.kind, "followed-call");
    assert.equal(result.blocks[1]?.startRva, 0x1007);
    assert.equal(result.blocks[2]?.kind, "followed-return");
    assert.equal(result.blocks[2]?.startRva, 0x100f);
    assert.equal(assertKnownReturnTarget(returnTarget).rva, 0x100f);
    assert.ok(!result.blocks.some(block => block.startRva === 0x1005));
  }
);

void test("analyzePeEntrypointDisassembly follows BND return after x86 EH prolog", async () => {
  const bytes = new Uint8Array([
    // Intel SDM Vol. 2 PUSH/CALL/RET encodings. This mirrors the MSVC x86 EH
    // prolog shape that copies the saved return from [EBP-8] before BND RET.
    0x6a, 0x14,
    0x68, 0x70, 0x7d, 0x43, 0x00,
    0xe8, 0x04, 0x00, 0x00, 0x00,
    0xc3,
    0xcc, 0xcc, 0xcc,
    0x68, 0x10, 0x08, 0x42, 0x00,
    0x64, 0xff, 0x35, 0x00, 0x00, 0x00, 0x00,
    0x8b, 0x44, 0x24, 0x10,
    0x89, 0x6c, 0x24, 0x10,
    0x8d, 0x6c, 0x24, 0x10,
    0x2b, 0xe0,
    0x53,
    0x56,
    0x57,
    0x50,
    0xff, 0x75, 0xf8,
    0xf2, 0xc3
  ]);
  const result = await analyzeRealEntrypoint(bytes);
  const bndReturn = result.blocks.find(block => block.startRva === 0x1010)?.instructions.at(-1);

  assert.equal(bndReturn?.text, "bnd ret");
  assert.equal(assertKnownReturnTarget(bndReturn?.target).rva, 0x100c);
  assert.ok(result.blocks.some(
    block => block.kind === "followed-return" && block.startRva === 0x100c
  ));
  assert.ok(
    !result.issues.includes("Entrypoint preview stopped at return with unknown stack target.")
  );
});

void test("analyzePeEntrypointDisassembly does not reuse far-ret released arguments", async () => {
  // Intel SDM Vol. 2 RET: far returns pop EIP then CS before imm16 cleanup.
  // https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
  const scenario = createFarReturnReleasedArgumentScenario();
  const result = await analyzeScriptedEntrypoint(scenario.instructions);
  const returnedBlock = result.blocks.find(block => block.startRva === scenario.returnSiteRva);
  const returnedRet = returnedBlock?.instructions.at(-1)?.target;

  assert.deepEqual(returnedRet, { kind: "return", reason: "unknown" });
});

void test(
  "analyzePeEntrypointDisassembly keeps separate return contexts for one callee",
  async () => {
    const bytes = new Uint8Array([
      0xe8, 0x0b, 0x00, 0x00, 0x00,
      0x90,
      0xe8, 0x05, 0x00, 0x00, 0x00,
      0xc3,
      0x90, 0x90, 0x90, 0x90,
      0xc3
    ]);
    const result = await analyzeRealEntrypoint(bytes);
    const calleeBlocks = result.blocks.filter(block => block.kind === "followed-call");

    assert.equal(calleeBlocks.length, 2);
    assert.deepEqual(calleeBlocks.map(block => block.sourceInstructionRva), [0x1000, 0x1006]);
    assert.ok(result.blocks.some(
      block => block.kind === "followed-return" && block.startRva === 0x100b
    ));
  }
);
