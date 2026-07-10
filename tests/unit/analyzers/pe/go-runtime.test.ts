"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { analyzePeGoRuntime } from "../../../../analyzers/pe/go-runtime.js";
import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "../../../../analyzers/pe/optional-header/magic.js";
import { PE32_OPTIONAL_HEADER_MAGIC } from "../../../../analyzers/pe/optional-header/magic.js";
import { inlinePeSectionName } from "../../../../analyzers/pe/sections/name.js";
import type { PeSection, PeWindowsCore } from "../../../../analyzers/pe/types.js";
import { createGoRuntimeFixture } from "../../../fixtures/go-runtime.js";

const IMAGE_BASE = 0x1400_0000_0n;

// Exact section flags follow Microsoft PE "Section Flags":
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags

const section = (
  name: string,
  rva: number,
  rawOffset: number,
  size: number,
  characteristics: number
): PeSection => ({
  name: inlinePeSectionName(name),
  virtualAddress: rva,
  virtualSize: size,
  pointerToRawData: rawOffset,
  sizeOfRawData: size,
  characteristics
});

const createPeAdapterFixture = () => {
  const runtime = createGoRuntimeFixture("go1.20+", 8, IMAGE_BASE);
  const textOffset = 0;
  const headerOffset = 0x200;
  const moduleOffset = 0x600;
  const bytes = new Uint8Array(moduleOffset + runtime.moduleBytes.length);
  bytes.set(runtime.regions[0]!.bytes, textOffset);
  bytes.set(runtime.headerBytes, headerOffset);
  bytes.set(runtime.moduleBytes, moduleOffset);
  const sections = [
    // Microsoft PE: code + execute + read.
    section(".text", 0x1000, textOffset, 0x40, 0x6000_0020),
    // Microsoft PE: initialized data + read.
    section(".rdata", 0x2000, headerOffset, runtime.headerBytes.length, 0x4000_0040),
    // Microsoft PE: initialized data + read + write.
    section(".data", 0x3000, moduleOffset, runtime.moduleBytes.length, 0xc000_0040)
  ];
  const core = {
    opt: { Magic: PE32_PLUS_OPTIONAL_HEADER_MAGIC, ImageBase: IMAGE_BASE },
    sections
  } as PeWindowsCore;
  return { bytes, core, runtime };
};

const createPe32AdapterFixture = () => {
  const imageBase = 0x0040_0000n;
  const runtime = createGoRuntimeFixture("go1.20+", 4, imageBase);
  const bytes = new Uint8Array(0x600 + runtime.moduleBytes.length);
  bytes.set(runtime.regions[0]!.bytes, 0);
  bytes.set(runtime.headerBytes, 0x200);
  bytes.set(runtime.moduleBytes, 0x600);
  const sections = [
    section(".text", 0x1000, 0, 0x40, 0x6000_0020),
    section(".rdata", 0x2000, 0x200, runtime.headerBytes.length, 0x4000_0040),
    section(".data", 0x3000, 0x600, runtime.moduleBytes.length, 0xc000_0040)
  ];
  const core = {
    opt: { Magic: PE32_OPTIONAL_HEADER_MAGIC, ImageBase: imageBase },
    sections
  } as PeWindowsCore;
  return { bytes, core };
};

void test("analyzePeGoRuntime confirms mutually consistent PE runtime metadata", async () => {
  const fixture = createPeAdapterFixture();
  const file = new File([fixture.bytes], "go.exe");

  const result = await analyzePeGoRuntime(
    file,
    createFileRangeReader(file, 0, file.size),
    fixture.core
  );

  assert.ok(result);
  assert.equal(result.pcHeaderAddress, fixture.runtime.pcHeaderAddress);
  assert.equal(result.moduleDataAddress, fixture.runtime.moduleDataAddress);
  assert.deepEqual(result.functions.map(fn => fn.name), ["runtime.main", "main.main"]);
});

void test("analyzePeGoRuntime rejects a magic-only non-Go PE", async () => {
  const fixture = createPeAdapterFixture();
  fixture.bytes.fill(0, 0x600);
  const file = new File([fixture.bytes], "not-go.exe");

  const result = await analyzePeGoRuntime(
    file,
    createFileRangeReader(file, 0, file.size),
    fixture.core
  );

  assert.equal(result, null);
});

void test("analyzePeGoRuntime rejects corrupt moduledata", async () => {
  const fixture = createPeAdapterFixture();
  new DataView(fixture.bytes.buffer).setBigUint64(0x600, IMAGE_BASE + 0x2100n, true);
  const file = new File([fixture.bytes], "corrupt-go.exe");

  const result = await analyzePeGoRuntime(
    file,
    createFileRangeReader(file, 0, file.size),
    fixture.core
  );

  assert.equal(result, null);
});

void test("analyzePeGoRuntime ignores magic in executable sections", async () => {
  const fixture = createPeAdapterFixture();
  fixture.core.sections[1]!.characteristics = 0x6000_0020;
  const file = new File([fixture.bytes], "code-magic.exe");

  const result = await analyzePeGoRuntime(
    file,
    createFileRangeReader(file, 0, file.size),
    fixture.core
  );

  assert.equal(result, null);
});

void test("analyzePeGoRuntime parses PE32 preferred-VA pointers", async () => {
  const fixture = createPe32AdapterFixture();
  const file = new File([fixture.bytes], "go-386.exe");

  const result = await analyzePeGoRuntime(
    file,
    createFileRangeReader(file, 0, file.size),
    fixture.core
  );

  assert.equal(result?.pointerSize, 4);
  assert.equal(result?.functions.length, 2);
});

void test("analyzePeGoRuntime rejects ambiguous valid moduledata instances", async () => {
  const fixture = createPeAdapterFixture();
  const duplicateOffset = 0x700;
  const bytes = new Uint8Array(duplicateOffset + fixture.runtime.moduleBytes.length);
  bytes.set(fixture.bytes);
  bytes.set(fixture.runtime.moduleBytes, duplicateOffset);
  fixture.core.sections[2]!.sizeOfRawData = bytes.length - 0x600;
  fixture.core.sections[2]!.virtualSize = bytes.length - 0x600;
  const file = new File([bytes], "ambiguous-go.exe");

  const result = await analyzePeGoRuntime(
    file,
    createFileRangeReader(file, 0, file.size),
    fixture.core
  );

  assert.equal(result, null);
});

void test("analyzePeGoRuntime returns null without mapped data and on read failures", async () => {
  const fixture = createPeAdapterFixture();
  const noData = { ...fixture.core, sections: [fixture.core.sections[0]!] };
  const failingReader = {
    size: fixture.bytes.length,
    read: async (): Promise<DataView> => { throw new Error("read failed"); },
    readBytes: async (): Promise<Uint8Array> => { throw new Error("read failed"); }
  };

  const file = new File([fixture.bytes], "read-failure.exe");
  assert.equal(await analyzePeGoRuntime(file, failingReader, noData), null);
  assert.equal(await analyzePeGoRuntime(file, failingReader, fixture.core), null);
});
