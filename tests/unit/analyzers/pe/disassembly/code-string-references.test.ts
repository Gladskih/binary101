"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createPeCodeStringReferenceCollector } from "../../../../../analyzers/pe/disassembly/code-string-references.js";
import {
  fixtureIced,
  imm,
  instruction,
  mem,
  reg
} from "../../../../helpers/pe-entrypoint-emulation-fixture.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const IMAGE_BASE = 0x140000000n;
const RDATA_OFFSET = 0x100;
const RDATA_RVA = 0x3000;
const RDATA_SIZE = 0x200;
const TEXT_RVA = 0x1000;
const SECOND_STRING_DELTA = 0x40;
const INNER_STRING_DELTA = 6;

const asciiz = (text: string): Uint8Array =>
  new Uint8Array([...new TextEncoder().encode(text), 0]);

const asciiWithWideTerminator = (text: string): Uint8Array =>
  new Uint8Array([...new TextEncoder().encode(text), 0, 0]);

const ambiguousWideText = (): string =>
  // The ASCII bytes "ABCDEFGH" decode as these UTF-16LE code units.
  String.fromCharCode(0x4241, 0x4443, 0x4645, 0x4847);

const mojibakeWideText = (): string =>
  // Mixed symbol, CJK Extension A, common Han, and Hangul code units from bad UTF-16LE.
  String.fromCharCode(
    0x2b14, 0x3e23, 0x4a50, 0x6d4d, 0x4a50, 0x6d4d, 0xc2e9, 0x6c4e,
    0x4a5b, 0x6d4d, 0xc2e9, 0x6c48
  );

const localizedWideText = (): string =>
  // CJK Unified Ideographs plus Katakana; representative of localized UI text.
  String.fromCharCode(0x65e5, 0x672c, 0x8a9e, 0x30c6, 0x30b9, 0x30c8);

const utf16z = (text: string): Uint8Array => {
  const bytes = new Uint8Array((text.length + 1) * Uint16Array.BYTES_PER_ELEMENT);
  for (let index = 0; index < text.length; index += 1) {
    bytes[index * 2] = text.charCodeAt(index) & 0xff;
    bytes[index * 2 + 1] = text.charCodeAt(index) >> 8;
  }
  return bytes;
};

const createReader = (
  entries: Array<{ rva: number; bytes: Uint8Array }>
): { reader: MockFile; rvaToOff: (rva: number) => number | null } => {
  const bytes = new Uint8Array(RDATA_OFFSET + RDATA_SIZE);
  bytes.fill(0xff, RDATA_OFFSET);
  entries.forEach(entry => bytes.set(entry.bytes, RDATA_OFFSET + entry.rva - RDATA_RVA));
  return {
    reader: new MockFile(bytes),
    rvaToOff: rva => rva >= RDATA_RVA && rva < RDATA_RVA + RDATA_SIZE
      ? RDATA_OFFSET + rva - RDATA_RVA
      : null
  };
};

const imageVa = (rva: number): bigint => IMAGE_BASE + BigInt(rva);

void test("collector resolves direct ASCII and UTF-16 code string references", async () => {
  const wideRva = RDATA_RVA + SECOND_STRING_DELTA;
  const { reader, rvaToOff } = createReader([
    { rva: RDATA_RVA, bytes: asciiz("steam://open") },
    { rva: wideRva, bytes: utf16z("caption") }
  ]);
  const collector = createPeCodeStringReferenceCollector(fixtureIced, {
    imageBase: IMAGE_BASE,
    rvaToOff
  });

  collector.record(instruction("Lea", [reg("RCX"), mem("UInt64", "RIP", imageVa(RDATA_RVA))], {
    ip: imageVa(TEXT_RVA),
    length: 1
  }));
  collector.record(instruction("Mov", [reg("RDX"), imm(imageVa(wideRva), "Immediate64")], {
    ip: imageVa(TEXT_RVA + 1),
    length: 1
  }));
  const references = await collector.references(reader);

  assert.deepEqual(references.map(reference => ({
    rva: reference.rva,
    encoding: reference.encoding,
    byteLength: reference.byteLength,
    text: reference.text,
    instructionRvas: reference.instructionRvas
  })), [
    {
      rva: RDATA_RVA,
      encoding: "ascii",
      byteLength: 12,
      text: "steam://open",
      instructionRvas: [TEXT_RVA]
    },
    {
      rva: wideRva,
      encoding: "utf-16le",
      byteLength: 14,
      text: "caption",
      instructionRvas: [TEXT_RVA + 1]
    }
  ]);
});

void test("collector merges duplicate code references to the same string", async () => {
  const { reader, rvaToOff } = createReader([{ rva: RDATA_RVA, bytes: asciiz("kernel32") }]);
  const collector = createPeCodeStringReferenceCollector(fixtureIced, {
    imageBase: IMAGE_BASE,
    rvaToOff
  });

  collector.record(instruction("Lea", [reg("RCX"), mem("UInt64", "RIP", imageVa(RDATA_RVA))], {
    ip: imageVa(TEXT_RVA),
    length: 1
  }));
  collector.record(instruction("Push", [imm(imageVa(RDATA_RVA), "Immediate64")], {
    ip: imageVa(TEXT_RVA + 4),
    length: 1
  }));
  const references = await collector.references(reader);

  assert.deepEqual(references.map(reference => ({
    rva: reference.rva,
    text: reference.text,
    instructionRvas: reference.instructionRvas
  })), [{
    rva: RDATA_RVA,
    text: "kernel32",
    instructionRvas: [TEXT_RVA, TEXT_RVA + 4]
  }]);
});

void test("collector prefers API-determined encoding for matching code strings", async () => {
  const { reader, rvaToOff } = createReader([{
    rva: RDATA_RVA,
    bytes: asciiWithWideTerminator("ABCDEFGH")
  }]);
  const collector = createPeCodeStringReferenceCollector(fixtureIced, {
    imageBase: IMAGE_BASE,
    rvaToOff
  });

  collector.record(instruction("Lea", [reg("RCX"), mem("UInt64", "RIP", imageVa(RDATA_RVA))], {
    ip: imageVa(TEXT_RVA),
    length: 1
  }));
  const references = await collector.references(reader, [{
    rva: RDATA_RVA,
    encoding: "utf-16le",
    byteLength: 8,
    text: ambiguousWideText(),
    callSites: []
  }]);

  assert.deepEqual(references.map(reference => ({
    rva: reference.rva,
    encoding: reference.encoding,
    text: reference.text,
    instructionRvas: reference.instructionRvas
  })), [{
    rva: RDATA_RVA,
    encoding: "utf-16le",
    text: ambiguousWideText(),
    instructionRvas: [TEXT_RVA]
  }]);
});

void test("collector keeps the Latin decoding when one address has ambiguous encodings", async () => {
  const { reader, rvaToOff } = createReader([{
    rva: RDATA_RVA,
    bytes: asciiWithWideTerminator("ABCDEFGH")
  }]);
  const collector = createPeCodeStringReferenceCollector(fixtureIced, {
    imageBase: IMAGE_BASE,
    rvaToOff
  });

  collector.record(instruction("Lea", [reg("RCX"), mem("UInt64", "RIP", imageVa(RDATA_RVA))], {
    ip: imageVa(TEXT_RVA),
    length: 1
  }));
  const references = await collector.references(reader);

  assert.deepEqual(references.map(reference => ({
    rva: reference.rva,
    encoding: reference.encoding,
    text: reference.text
  })), [{
    rva: RDATA_RVA,
    encoding: "ascii",
    text: "ABCDEFGH"
  }]);
});

void test("collector rejects implausible UTF-16 code strings without blocking CJK text", async () => {
  const { reader, rvaToOff } = createReader([
    { rva: RDATA_RVA, bytes: utf16z(mojibakeWideText()) },
    { rva: RDATA_RVA + SECOND_STRING_DELTA, bytes: utf16z(localizedWideText()) }
  ]);
  const collector = createPeCodeStringReferenceCollector(fixtureIced, {
    imageBase: IMAGE_BASE,
    rvaToOff
  });

  collector.record(instruction("Lea", [reg("RCX"), mem("UInt64", "RIP", imageVa(RDATA_RVA))], {
    ip: imageVa(TEXT_RVA),
    length: 1
  }));
  collector.record(instruction(
    "Lea",
    [reg("RDX"), mem("UInt64", "RIP", imageVa(RDATA_RVA + SECOND_STRING_DELTA))],
    { ip: imageVa(TEXT_RVA + 1), length: 1 }
  ));
  const references = await collector.references(reader);

  assert.deepEqual(references.map(reference => ({
    rva: reference.rva,
    encoding: reference.encoding,
    text: reference.text,
    instructionRvas: reference.instructionRvas
  })), [{
    rva: RDATA_RVA + SECOND_STRING_DELTA,
    encoding: "utf-16le",
    text: localizedWideText(),
    instructionRvas: [TEXT_RVA + 1]
  }]);
});

void test("collector folds references to strings contained inside a larger buffer", async () => {
  const { reader, rvaToOff } = createReader([{ rva: RDATA_RVA, bytes: asciiz("kernel32.dll") }]);
  const collector = createPeCodeStringReferenceCollector(fixtureIced, {
    imageBase: IMAGE_BASE,
    rvaToOff
  });

  collector.record(instruction("Lea", [reg("RCX"), mem("UInt64", "RIP", imageVa(RDATA_RVA))], {
    ip: imageVa(TEXT_RVA),
    length: 1
  }));
  collector.record(instruction(
    "Lea",
    [reg("RDX"), mem("UInt64", "RIP", imageVa(RDATA_RVA + INNER_STRING_DELTA))],
    { ip: imageVa(TEXT_RVA + 1), length: 1 }
  ));
  const references = await collector.references(reader);

  assert.deepEqual(references.map(reference => ({
    rva: reference.rva,
    encoding: reference.encoding,
    text: reference.text,
    instructionRvas: reference.instructionRvas
  })), [{
    rva: RDATA_RVA,
    encoding: "ascii",
    text: "kernel32.dll",
    instructionRvas: [TEXT_RVA, TEXT_RVA + 1]
  }]);
});

void test("collector skips short, unmapped, and unterminated code string candidates", async () => {
  const { reader, rvaToOff } = createReader([
    { rva: RDATA_RVA, bytes: asciiz("abc") },
    { rva: RDATA_RVA + SECOND_STRING_DELTA, bytes: new TextEncoder().encode("unterminated") }
  ]);
  const collector = createPeCodeStringReferenceCollector(fixtureIced, {
    imageBase: IMAGE_BASE,
    rvaToOff
  });

  [
    RDATA_RVA,
    RDATA_RVA + SECOND_STRING_DELTA,
    RDATA_RVA + RDATA_SIZE
  ].forEach((rva, index) => collector.record(instruction(
    "Lea",
    [reg("RCX"), mem("UInt64", "RIP", imageVa(rva))],
    { ip: imageVa(TEXT_RVA + index), length: 1 }
  )));

  assert.deepEqual(await collector.references(reader), []);
});
