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
const HEADER_RVA_LIMIT = 0x200;
const DOS_STUB_FRAGMENT_RVA = 0x50;
const RDATA_RVA = 0x3000;
const RDATA_OFFSET = 0x300;
const TEXT_RVA = 0x1000;

const asciiz = (text: string): Uint8Array =>
  new Uint8Array([...new TextEncoder().encode(text), 0]);

const createReader = (): { reader: MockFile; rvaToOff: (rva: number) => number | null } => {
  const bytes = new Uint8Array(RDATA_OFFSET + 0x100);
  bytes.set(asciiz("is program cannot be run in DOS mode."), DOS_STUB_FRAGMENT_RVA);
  bytes.set(asciiz("config.ini"), RDATA_OFFSET);
  return {
    reader: new MockFile(bytes),
    rvaToOff: rva => {
      if (rva < HEADER_RVA_LIMIT) return rva;
      return rva >= RDATA_RVA && rva < RDATA_RVA + 0x100 ? RDATA_OFFSET + rva - RDATA_RVA : null;
    }
  };
};

const imageVa = (rva: number): bigint => IMAGE_BASE + BigInt(rva);

void test("collector skips strings from the mapped PE headers", async () => {
  const { reader, rvaToOff } = createReader();
  const collector = createPeCodeStringReferenceCollector(fixtureIced, {
    imageBase: IMAGE_BASE,
    headerRvaLimit: HEADER_RVA_LIMIT,
    rvaToOff
  });

  collector.record(instruction("Mov", [reg("EAX"), imm(DOS_STUB_FRAGMENT_RVA)], {
    ip: imageVa(TEXT_RVA),
    length: 1
  }));

  assert.deepEqual(await collector.references(reader), []);
});

void test("collector keeps section strings when header filtering is enabled", async () => {
  const { reader, rvaToOff } = createReader();
  const collector = createPeCodeStringReferenceCollector(fixtureIced, {
    imageBase: IMAGE_BASE,
    headerRvaLimit: HEADER_RVA_LIMIT,
    rvaToOff
  });

  collector.record(instruction("Mov", [reg("EAX"), imm(imageVa(RDATA_RVA), "Immediate64")], {
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
    text: "config.ini"
  }]);
});
