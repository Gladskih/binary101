"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeDosStubCode } from "../../analyzers/pe/core/dos-stub-code.js";
import { parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { MockFile } from "../helpers/mock-file.js";

const FIXED_DOS_HEADER_SIZE = 0x40;
const encoder = new TextEncoder();

const COMMON_STUB_MESSAGE = "This program cannot be run in DOS mode.\r\n";
const DOS_SIGNATURE_MZ = 0x5a4d;
const DOS_E_LFANEW_OFFSET = 0x3c;
const IMAGE_FILE_MACHINE_I386 = 0x014c;

const pushPopThenDxCode = (dxOffset: number, exitCode = 1): number[] => [
  0x0e, 0x1f, // 8086 opcodes: push cs; pop ds.
  0xba, dxOffset & 0xff, dxOffset >>> 8, // mov dx, imm16.
  0xb4, 0x09, 0xcd, 0x21, // MS-DOS INT 21h AH=09h string print.
  0xb8, exitCode, 0x4c, 0xcd, 0x21 // MS-DOS INT 21h AH=4Ch process terminate.
];

const dxThenPushPopCode = (dxOffset: number, exitCode = 0): number[] => [
  0xba, dxOffset & 0xff, dxOffset >>> 8, // mov dx, imm16.
  0x0e, 0x1f, // push cs; pop ds.
  0xb4, 0x09, 0xcd, 0x21,
  0xb8, exitCode, 0x4c, 0xcd, 0x21
];

const withMessage = (code: number[], message = COMMON_STUB_MESSAGE): Uint8Array => {
  const messageBytes = encoder.encode(`${message}$`);
  const bytes = new Uint8Array(code.length + messageBytes.length);
  bytes.set(code);
  bytes.set(messageBytes, code.length);
  return bytes;
};

const analyzeLoadModule = (
  bytes: Uint8Array,
  eCs = 0,
  eIp = 0,
  eCparhdr = 4,
  loader = async (): Promise<unknown> => {
    throw new Error("disassembler should not load for common stubs");
  }
): ReturnType<typeof analyzePeDosStubCode> => {
  const headerBytes = eCparhdr * 16;
  const stubBytes = headerBytes > FIXED_DOS_HEADER_SIZE
    ? new Uint8Array(headerBytes - FIXED_DOS_HEADER_SIZE + bytes.length)
    : bytes;
  if (stubBytes !== bytes) stubBytes.set(bytes, headerBytes - FIXED_DOS_HEADER_SIZE);
  return analyzePeDosStubCode(
    { e_cparhdr: eCparhdr, e_cs: eCs, e_ip: eIp },
    stubBytes,
    headerBytes + bytes.length,
    loader
  );
};

void test("analyzePeDosStubCode recognizes the common push/pop before DX DOS stub", async () => {
  const code = pushPopThenDxCode(0x0e);

  const result = await analyzeLoadModule(withMessage(code));

  assert.equal(result.kind, "standard-print-exit");
  assert.equal(result.pattern, "push-pop-then-dx");
  assert.equal(result.messageOffset, 0x0e);
  assert.equal(result.message, COMMON_STUB_MESSAGE);
  assert.equal(result.exitCode, 1);
  assert.equal(result.instructions.length, 7);
  assert.equal("code" in result.instructions[0]!, false);
});

void test("analyzePeDosStubCode recognizes the common DX before push/pop DOS stub", async () => {
  const code = dxThenPushPopCode(0x0e);

  const result = await analyzeLoadModule(withMessage(code));

  assert.equal(result.kind, "standard-print-exit");
  assert.equal(result.pattern, "dx-then-push-pop");
  assert.equal(result.messageOffset, 0x0e);
  assert.equal(result.message, COMMON_STUB_MESSAGE);
  assert.equal(result.exitCode, 0);
});

void test("analyzePeDosStubCode resolves DS:DX through e_cs for the printed message", async () => {
  const eCs = 1;
  const entryOffset = eCs * 16;
  const messageOffset = 0x20;
  const dxOffset = messageOffset - entryOffset;
  const loadModule = new Uint8Array(messageOffset + COMMON_STUB_MESSAGE.length + 1);
  loadModule.set(pushPopThenDxCode(dxOffset), entryOffset);
  loadModule.set(encoder.encode(`${COMMON_STUB_MESSAGE}$`), messageOffset);

  const result = await analyzeLoadModule(loadModule, eCs, 0);

  assert.equal(result.kind, "standard-print-exit");
  assert.equal(result.messageOffset, messageOffset);
  assert.equal(result.message, COMMON_STUB_MESSAGE);
});

void test("analyzePeDosStubCode handles extra MZ header paragraphs before the load module", async () => {
  const code = pushPopThenDxCode(0x0e);

  const result = await analyzeLoadModule(withMessage(code), 0, 0, 5);

  assert.equal(result.kind, "standard-print-exit");
  assert.equal(result.messageOffset, 0x0e);
});

void test("analyzePeDosStubCode rejects the common opcode pattern when DX is not a valid message", async () => {
  const result = await analyzeLoadModule(new Uint8Array(pushPopThenDxCode(0xff)));

  assert.equal(result.kind, "custom-or-unrecognized");
  assert.ok(result.notes?.some(note => /offset|message/i.test(note)));
});

void test("analyzePeDosStubCode rejects empty and unterminated DOS print strings", async () => {
  const empty = await analyzeLoadModule(withMessage(pushPopThenDxCode(0x0e), ""));
  const unterminated = new Uint8Array([...pushPopThenDxCode(0x0e), 0x41, 0x42]);

  const unterminatedResult = await analyzeLoadModule(unterminated);

  assert.equal(empty.kind, "custom-or-unrecognized");
  assert.ok(empty.notes?.some(note => /empty/i.test(note)));
  assert.equal(unterminatedResult.kind, "custom-or-unrecognized");
  assert.ok(unterminatedResult.notes?.some(note => /terminated/i.test(note)));
});

void test("analyzePeDosStubCode previews custom code only until a control-flow instruction", async () => {
  const bytes = new Uint8Array([0x4d, 0x5a, 0xeb, 0x00]);

  const result = await analyzePeDosStubCode(
    { e_cparhdr: 4, e_cs: 0, e_ip: 0 },
    bytes,
    FIXED_DOS_HEADER_SIZE + bytes.length
  );

  assert.equal(result.kind, "custom-or-unrecognized");
  assert.deepEqual(result.instructions.map(instruction => instruction.text), ["dec bp", "pop dx", "jmp short 4"]);
  assert.ok(result.notes?.some(note => /another MZ signature/i.test(note)));
  assert.ok(result.notes?.some(note => /control-flow/i.test(note)));
});

void test("analyzePeDosStubCode reports unavailable analysis for malformed offsets", async () => {
  const badHeader = await analyzePeDosStubCode({ e_cparhdr: 0, e_cs: 0, e_ip: 0 }, new Uint8Array(), 0x80);
  const badEntrypoint = await analyzeLoadModule(new Uint8Array([0x90]), 0, 2);

  assert.equal(badHeader.kind, "unavailable");
  assert.ok(badHeader.notes?.some(note => /header size/i.test(note)));
  assert.equal(badEntrypoint.kind, "unavailable");
  assert.ok(badEntrypoint.notes?.some(note => /entrypoint/i.test(note)));
});

void test("analyzePeDosStubCode reports unavailable when fallback disassembly fails", async () => {
  const result = await analyzeLoadModule(new Uint8Array([0x90]), 0, 0, 4, async () => {
    throw new Error("boom");
  });

  assert.equal(result.kind, "unavailable");
  assert.ok(result.notes?.some(note => /disassembler is not available/i.test(note)));
});

void test("analyzePeDosStubCode catches runtime failures from fallback disassembly", async () => {
  const throwingModule = {
    Code: { INVALID: -1 },
    Decoder: class {
      constructor() {
        throw new Error("decoder boom");
      }
    },
    DecoderOptions: { None: 0 },
    FlowControl: { Next: 0 },
    Formatter: class {
      format(): string {
        return "";
      }
      free(): void {}
    },
    FormatterSyntax: { Nasm: 0 },
    Instruction: class {
      free(): void {}
    }
  };

  const result = await analyzeLoadModule(new Uint8Array([0x90]), 0, 0, 4, async () => throwingModule);

  assert.equal(result.kind, "unavailable");
  assert.ok(result.notes?.some(note => /disassembly failed/i.test(note)));
});

void test("parsePeHeaders uses DS:DX message instead of printable run scan for standard stubs", async () => {
  const code = pushPopThenDxCode(0x0e);
  const loadModule = withMessage(code);
  const peOffset = FIXED_DOS_HEADER_SIZE + loadModule.length;
  const bytes = new Uint8Array(peOffset + 24);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, DOS_SIGNATURE_MZ, true);
  view.setUint16(0x08, 4, true);
  view.setUint32(DOS_E_LFANEW_OFFSET, peOffset, true);
  bytes.set(loadModule, FIXED_DOS_HEADER_SIZE);
  bytes.set([0x50, 0x45, 0x00, 0x00], peOffset);
  view.setUint16(peOffset + 4, IMAGE_FILE_MACHINE_I386, true);

  const parsed = await parsePeHeaders(new MockFile(bytes, "dos-stub-message.exe"));

  assert.ok(parsed);
  assert.equal(parsed.dos.stub.kind, "standard");
  assert.equal(parsed.dos.stub.code?.message, COMMON_STUB_MESSAGE);
  assert.equal(parsed.dos.stub.strings, undefined);
});
