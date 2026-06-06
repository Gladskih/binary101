"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86";
import { collectSecurityCookieOperandNotes } from "../../analyzers/pe/disassembly/entrypoint/security-cookie-notes.js";
import type { IcedModule } from "../../analyzers/pe/disassembly/entrypoint/iced.js";

const icedModule = iced as unknown as IcedModule;

const collectNotesFromBytes = (bitness: number, bytes: number[]): string[] => {
  const decoder = new iced.Decoder(bitness, new Uint8Array(bytes), iced.DecoderOptions.None);
  const instruction = new iced.Instruction();
  try {
    decoder.decodeOut(instruction);
    return collectSecurityCookieOperandNotes(icedModule, instruction);
  } finally {
    instruction.free();
    decoder.free();
  }
};

void test("collectSecurityCookieOperandNotes marks MSVC x86 default cookie", () => {
  // Visual Studio VCRuntime gs_support.c defines the x86 default as 0xBB40E64E.
  assert.deepEqual(
    collectNotesFromBytes(32, [0xb8, 0x4e, 0xe6, 0x40, 0xbb]),
    ["MSVC-compatible x86 /GS default security cookie (0xBB40E64E)."]
  );
});

void test("collectSecurityCookieOperandNotes marks MSVC x64 default cookie", () => {
  // Visual Studio VCRuntime gs_support.c defines the x64 default as 0x00002B992DDFA232.
  assert.deepEqual(
    collectNotesFromBytes(64, [0x48, 0xb8, 0x32, 0xa2, 0xdf, 0x2d, 0x99, 0x2b, 0x00, 0x00]),
    ["MSVC-compatible x64 /GS default security cookie (0x00002B992DDFA232)."]
  );
});

void test("collectSecurityCookieOperandNotes marks MSVC x86 high-word repair constant", () => {
  // Visual Studio VCRuntime gs_support.c uses 0x4711 when the x86 cookie high word is zero.
  assert.deepEqual(
    collectNotesFromBytes(32, [0x0d, 0x11, 0x47, 0x00, 0x00]),
    ["MSVC x86 /GS high-word repair constant for cookies with upper 16 bits zero."]
  );
});

void test("collectSecurityCookieOperandNotes ignores instructions without known immediates", () => {
  assert.deepEqual(collectNotesFromBytes(64, [0x90]), []);
});
