"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import * as realIced from "iced-x86";
import { createFileRangeReader } from "../../../../../../analyzers/file-range-reader.js";
import { analyzePeEntrypointDisassembly } from "../../../../../../analyzers/pe/disassembly/index.js";
import type { IcedModule } from "../../../../../../analyzers/pe/disassembly/entrypoint/iced.js";
import {
  IMAGE_FILE_MACHINE_I386,
  createExecutableSection
} from "../../../../../helpers/pe-entrypoint-disassembly-fixture.js";
import { MockFile } from "../../../../../helpers/mock-file.js";

const realIcedModule = realIced as unknown as IcedModule;

void test("analyzePeEntrypointDisassembly cleans x86 stdcall import arguments", async () => {
  const bytes = new Uint8Array([
    // Intel SDM Vol. 2 CALL/PUSH/RET encodings; Microsoft x86 __stdcall
    // callees pop fixed arguments before returning.
    0xe8, 0x0b, 0x00, 0x00, 0x00,
    0x90,
    0xc3,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0x55,
    0x8b, 0xec,
    0x53,
    0x56,
    0x57,
    0x6a, 0x00,
    0xff, 0x15, 0x00, 0x20, 0x40, 0x00,
    0x33, 0xc0,
    0x5f,
    0x5e,
    0x5b,
    0x5d,
    0xc3
  ]);
  const result = await analyzePeEntrypointDisassembly(
    createFileRangeReader(new MockFile(bytes, "stdcall-import.exe"), 0, bytes.length),
    {
      coffMachine: IMAGE_FILE_MACHINE_I386,
      is64Bit: false,
      imageBase: 0x400000n,
      entrypointRva: 0x1000,
      rvaToOff: rva => rva - 0x1000,
      sections: [
        createExecutableSection({ virtualSize: bytes.length, sizeOfRawData: bytes.length })
      ],
      imports: {
        thunkEntrySize: 4,
        entries: [{
          dll: "KERNEL32.dll",
          originalFirstThunkRva: 0x3000,
          timeDateStamp: 0,
          forwarderChain: 0,
          firstThunkRva: 0x2000,
          lookupSource: "import-lookup-table",
          thunkTableTerminated: true,
          functions: [{ name: "FreeLibrary" }]
        }]
      }
    },
    async () => realIcedModule
  );
  const calleeReturn = result.blocks[1]?.instructions.at(-1)?.target;

  assert.equal(result.blocks[1]?.startRva, 0x1010);
  assert.deepEqual(calleeReturn, { kind: "return", rva: 0x1005, followed: true });
  assert.ok(result.blocks.some(
    block => block.kind === "followed-return" && block.startRva === 0x1005
  ));
});
