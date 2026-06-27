"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { selectPeCodeStringReferences } from "../../../../../analyzers/pe/disassembly/code-string-selection.js";
import type { PeCodeStringReference } from "../../../../../analyzers/pe/disassembly/index.js";

const STRING_RVA = 0x3000;
const TEXT_RVA = 0x1000;

const codeReference = (
  encoding: PeCodeStringReference["encoding"],
  text: string
): PeCodeStringReference => ({
  rva: STRING_RVA,
  encoding,
  byteLength: text.length,
  text,
  instructionRvas: [TEXT_RVA]
});

void test("selectPeCodeStringReferences handles an empty reference list", () => {
  assert.deepEqual(selectPeCodeStringReferences([], []), []);
});

void test("selectPeCodeStringReferences keeps the simplest encoding for equal text", () => {
  const references = [
    codeReference("utf-8", "config.ini"),
    codeReference("ascii", "config.ini")
  ];

  assert.deepEqual(selectPeCodeStringReferences(references, []).map(reference => ({
    rva: reference.rva,
    encoding: reference.encoding,
    text: reference.text,
    instructionRvas: reference.instructionRvas
  })), [{
    rva: STRING_RVA,
    encoding: "ascii",
    text: "config.ini",
    instructionRvas: [TEXT_RVA]
  }]);
});

void test("selectPeCodeStringReferences does not fold unsafe byte ranges", () => {
  const references = [
    {
      ...codeReference("ascii", "outer"),
      byteLength: Number.MAX_SAFE_INTEGER
    },
    {
      ...codeReference("ascii", "n"),
      rva: STRING_RVA + 1,
      byteLength: 1
    }
  ];

  assert.deepEqual(selectPeCodeStringReferences(references, []).map(reference => ({
    rva: reference.rva,
    text: reference.text,
    instructionRvas: reference.instructionRvas
  })), [
    {
      rva: STRING_RVA,
      text: "outer",
      instructionRvas: [TEXT_RVA]
    },
    {
      rva: STRING_RVA + 1,
      text: "n",
      instructionRvas: [TEXT_RVA]
    }
  ]);
});
