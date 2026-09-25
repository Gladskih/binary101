"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86-disasm";
import { createInstruction } from "../../../../../../analyzers/pe/disassembly/entrypoint/instruction.js";

void test("createInstruction includes formatted text and operand notes", () => {
  const decoder = new iced.Decoder(
    32,
    new Uint8Array([0xb8, 0x4e, 0xe6, 0x40, 0xbb]),
    iced.DecoderOptions.None
  );
  const decoded = new iced.Instruction();
  try {
    decoder.decodeOut(decoded);
    assert.deepEqual(
      createInstruction(
        iced,
        decoded,
        { format: () => "mov eax,cookie", free: () => {} },
        0x1000,
        0x200
      ),
      {
        rva: 0x1000,
        fileOffset: 0x200,
        text: "mov eax,cookie",
        notes: ["MSVC-compatible x86 /GS default security cookie (0xBB40E64E)."]
      }
    );
  } finally {
    decoded.free();
    decoder.free();
  }
});
