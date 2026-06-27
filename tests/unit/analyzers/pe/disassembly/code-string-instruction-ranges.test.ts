"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createPeCodeStringReferenceCollector } from "../../../../../analyzers/pe/disassembly/code-string-references.js";
import {
  fixtureIced,
  imm,
  instruction,
  reg
} from "../../../../helpers/pe-entrypoint-emulation-fixture.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const IMAGE_BASE = 0x140000000n;
const TEXT_RVA = 0x1000;
const TEXT_DATA_DELTA = 0x40;
const TEXT_SIZE = 0x100;
const TEXT_STRING = "Hello from .text";

const asciiz = (text: string): Uint8Array =>
  new Uint8Array([...new TextEncoder().encode(text), 0]);

const createReader = (): { reader: MockFile; rvaToOff: (rva: number) => number | null } => {
  const bytes = new Uint8Array(TEXT_SIZE);
  bytes.set(asciiz(TEXT_STRING), 0);
  bytes.set(asciiz(TEXT_STRING), TEXT_DATA_DELTA);
  return {
    reader: new MockFile(bytes),
    rvaToOff: rva => rva >= TEXT_RVA && rva < TEXT_RVA + TEXT_SIZE
      ? rva - TEXT_RVA
      : null
  };
};

const imageVa = (rva: number): bigint => IMAGE_BASE + BigInt(rva);

void test("collector skips candidate strings that overlap decoded instructions", async () => {
  const { reader, rvaToOff } = createReader();
  const collector = createPeCodeStringReferenceCollector(fixtureIced, {
    imageBase: IMAGE_BASE,
    rvaToOff
  });

  collector.record(instruction("Mov", [reg("EAX"), imm(imageVa(TEXT_RVA), "Immediate64")], {
    ip: imageVa(TEXT_RVA),
    length: 4
  }));

  assert.deepEqual(await collector.references(reader), []);
});

void test("collector keeps executable-section data that was not decoded as instructions", async () => {
  const { reader, rvaToOff } = createReader();
  const collector = createPeCodeStringReferenceCollector(fixtureIced, {
    imageBase: IMAGE_BASE,
    rvaToOff
  });
  const dataRva = TEXT_RVA + TEXT_DATA_DELTA;

  collector.record(instruction("Mov", [reg("EAX"), imm(imageVa(dataRva), "Immediate64")], {
    ip: imageVa(TEXT_RVA),
    length: 4
  }));
  const references = await collector.references(reader);

  assert.deepEqual(references.map(reference => ({
    rva: reference.rva,
    encoding: reference.encoding,
    text: reference.text
  })), [{
    rva: dataRva,
    encoding: "ascii",
    text: TEXT_STRING
  }]);
});

void test("collector keeps decoded-instruction strings confirmed by API analysis", async () => {
  const { reader, rvaToOff } = createReader();
  const collector = createPeCodeStringReferenceCollector(fixtureIced, {
    imageBase: IMAGE_BASE,
    rvaToOff
  });

  collector.record(instruction("Mov", [reg("EAX"), imm(imageVa(TEXT_RVA), "Immediate64")], {
    ip: imageVa(TEXT_RVA),
    length: 4
  }));
  const references = await collector.references(reader, [{
    rva: TEXT_RVA,
    encoding: "ascii",
    byteLength: TEXT_STRING.length,
    text: TEXT_STRING,
    callSites: []
  }]);

  assert.deepEqual(references.map(reference => ({
    rva: reference.rva,
    encoding: reference.encoding,
    text: reference.text
  })), [{
    rva: TEXT_RVA,
    encoding: "ascii",
    text: TEXT_STRING
  }]);
});
