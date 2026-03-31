"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderSanity } from "../../renderers/pe/layout.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";

const createPeWithCoffTail = (overlaySize: number): PeParseResult =>
  ({
    overlaySize,
    imageSizeMismatch: false,
    debug: null,
    coff: {
      PointerToSymbolTable: 0x240,
      NumberOfSymbols: 1
    },
    coffStringTableSize: 0x26,
    sections: [
      {
        name: ".text",
        virtualSize: 0x200,
        virtualAddress: 0x1000,
        sizeOfRawData: 0x200,
        pointerToRawData: 0x40,
        characteristics: 0x60000020
      }
    ],
    opt: { AddressOfEntryPoint: 0x1000 }
  }) as unknown as PeParseResult;

void test("renderSanity does not flag COFF symbol and string tables after the last section", () => {
  const out: string[] = [];

  renderSanity(createPeWithCoffTail(0x38), out);

  const html = out.join("");
  assert.ok(!html.includes("Overlay after last section"));
  assert.ok(html.includes("No obvious structural issues"));
});

void test("renderSanity still reports bytes that remain after the known COFF tail", () => {
  const out: string[] = [];

  renderSanity(createPeWithCoffTail(0x48), out);

  assert.ok(out.join("").includes("Overlay after last section: 16 B (16 bytes)."));
});

void test("renderSanity does not flag explicit trailing alignment padding after the known COFF tail", () => {
  const out: string[] = [];

  renderSanity(
    { ...createPeWithCoffTail(0x1ff), trailingAlignmentPaddingSize: 0x1cb } as PeParseResult,
    out
  );

  assert.ok(!out.join("").includes("Overlay after last section"));
});
