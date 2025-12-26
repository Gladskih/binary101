"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ParseForUiResult } from "../../analyzers/index.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";
import type { BmpParseResult } from "../../analyzers/bmp/types.js";
import { renderAnalysisIntoUi } from "../../ui/render-analysis.js";

void test("renderAnalysisIntoUi renders ELF output and updates visibility flags", () => {
  const elf = {
    ident: {
      classByte: 2,
      className: "ELF64",
      dataByte: 1,
      dataName: "Little endian",
      osabi: 0,
      abiVersion: 0
    },
    header: {
      type: 2,
      typeName: "Executable",
      machine: 62,
      machineName: "x86-64",
      entry: 0x400000n,
      phoff: 0n,
      shoff: 0n,
      flags: 0,
      ehsize: 64,
      phentsize: 56,
      phnum: 0,
      shentsize: 64,
      shnum: 0,
      shstrndx: 0
    },
    programHeaders: [],
    sections: [],
    issues: [],
    is64: true,
    littleEndian: true,
    fileSize: 0
  } as unknown as ElfParseResult;
  const result: ParseForUiResult = { analyzer: "elf", parsed: elf };

  const termElement = { textContent: "", hidden: true } as unknown as HTMLElement;
  const valueElement = { innerHTML: "", hidden: true } as unknown as HTMLElement;

  renderAnalysisIntoUi(result, {
    buildPreview: () => null,
    attachGuards: () => {},
    termElement,
    valueElement
  });

  assert.equal(termElement.hidden, false);
  assert.equal(termElement.textContent, "ELF details");
  assert.equal(valueElement.hidden, false);
  assert.ok(valueElement.innerHTML.includes("Instruction sets"));
});

void test("renderAnalysisIntoUi renders BMP output", () => {
  const bmp = {
    isBmp: true,
    fileSize: 58,
    fileHeader: {
      signature: "BM",
      declaredFileSize: 58,
      reserved1: 0,
      reserved2: 0,
      pixelArrayOffset: 54,
      truncated: false
    },
    dibHeader: {
      headerSize: 40,
      headerKind: "BITMAPINFOHEADER",
      width: 1,
      height: 1,
      signedHeight: 1,
      topDown: false,
      planes: 1,
      bitsPerPixel: 24,
      compression: 0,
      compressionName: "BI_RGB (uncompressed)",
      imageSize: 4,
      xPixelsPerMeter: null,
      yPixelsPerMeter: null,
      colorsUsed: 0,
      importantColors: 0,
      masks: null,
      truncated: false
    },
    palette: null,
    pixelArray: {
      offset: 54,
      availableBytes: 4,
      rowStride: 4,
      expectedBytes: 4n,
      truncated: false,
      extraBytes: 0n
    },
    issues: []
  } as unknown as BmpParseResult;
  const result: ParseForUiResult = { analyzer: "bmp", parsed: bmp };

  const termElement = { textContent: "", hidden: true } as unknown as HTMLElement;
  const valueElement = { innerHTML: "", hidden: true } as unknown as HTMLElement;

  renderAnalysisIntoUi(result, {
    buildPreview: () => null,
    attachGuards: () => {},
    termElement,
    valueElement
  });

  assert.equal(termElement.hidden, false);
  assert.equal(termElement.textContent, "BMP details");
  assert.equal(valueElement.hidden, false);
  assert.ok(valueElement.innerHTML.includes("BMP structure"));
});
