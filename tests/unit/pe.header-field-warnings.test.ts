"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { collectPeHeaderFieldWarnings } from "../../analyzers/pe/layout/header-field-warnings.js";
import { createWindowsLayoutSubject } from "../fixtures/pe-layout-warning-subject.js";

// Microsoft PE/COFF file and DLL characteristic bits used by these header-warning fixtures.
const IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020;
const COMIMAGE_FLAGS_ILONLY = 0x00000001;
const COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002;
// Microsoft PE/COFF optional header magic values: 0x10b is PE32, 0x20b is PE32+.
const PE32_OPTIONAL_HEADER_MAGIC = 0x10b;
const PE32_PLUS_OPTIONAL_HEADER_MAGIC = 0x20b;

void test("collectPeHeaderFieldWarnings reports section counts above the loader limit", () => {
  const pe = createWindowsLayoutSubject();
  pe.coff.NumberOfSections = 97;

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(pe), [
    "NumberOfSections is greater than 96; the Windows loader limits image section count to 96."
  ]);
});

void test("collectPeHeaderFieldWarnings accepts the Windows loader section count limit", () => {
  const pe = createWindowsLayoutSubject();
  pe.coff.NumberOfSections = 96;

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(pe), []);
});

void test("collectPeHeaderFieldWarnings reports missing executable-image characteristic", () => {
  const pe = createWindowsLayoutSubject();
  pe.coff.Characteristics = 0;

  assert.ok(collectPeHeaderFieldWarnings(pe).includes(
    "COFF Characteristics does not set IMAGE_FILE_EXECUTABLE_IMAGE; the PE spec says this indicates a linker error."
  ));
});

void test("collectPeHeaderFieldWarnings accepts executable-image characteristic", () => {
  const pe = createWindowsLayoutSubject();
  pe.coff.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(pe), []);
});

void test("collectPeHeaderFieldWarnings reports SectionAlignment below FileAlignment", () => {
  const pe = createWindowsLayoutSubject();
  pe.opt.SectionAlignment = 0x200;
  pe.opt.FileAlignment = 0x1000;

  assert.ok(
    collectPeHeaderFieldWarnings(pe).includes(
      "SectionAlignment is smaller than FileAlignment; PE images require SectionAlignment >= FileAlignment."
    )
  );
});

void test("collectPeHeaderFieldWarnings accepts equal or larger SectionAlignment", () => {
  const equal = createWindowsLayoutSubject();
  equal.opt.SectionAlignment = 0x1000;
  equal.opt.FileAlignment = 0x1000;
  const larger = createWindowsLayoutSubject();
  larger.opt.SectionAlignment = 0x2000;
  larger.opt.FileAlignment = 0x1000;

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(equal), []);
  assert.deepStrictEqual(collectPeHeaderFieldWarnings(larger), []);
});

void test("collectPeHeaderFieldWarnings reports invalid FileAlignment values", () => {
  const nonPowerOfTwo = createWindowsLayoutSubject();
  nonPowerOfTwo.opt.FileAlignment = 0x180;
  const tooSmall = createWindowsLayoutSubject();
  tooSmall.opt.FileAlignment = 0x100;
  const tooLarge = createWindowsLayoutSubject();
  tooLarge.opt.SectionAlignment = 0x40000;
  tooLarge.opt.FileAlignment = 0x20000;
  const expected = "FileAlignment is not a power of two between 512 and 64K inclusive.";

  assert.ok(collectPeHeaderFieldWarnings(nonPowerOfTwo).includes(expected));
  assert.ok(collectPeHeaderFieldWarnings(tooSmall).includes(expected));
  assert.ok(collectPeHeaderFieldWarnings(tooLarge).includes(expected));
});

void test("collectPeHeaderFieldWarnings accepts standard FileAlignment", () => {
  const pe = createWindowsLayoutSubject();
  pe.opt.FileAlignment = 0x200;

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(pe), []);
});

void test("collectPeHeaderFieldWarnings reports unaligned ImageBase", () => {
  const pe = createWindowsLayoutSubject();
  pe.opt.ImageBase = 0x140001000n;

  assert.ok(collectPeHeaderFieldWarnings(pe).includes("ImageBase is not a multiple of 64K."));
});

void test("collectPeHeaderFieldWarnings accepts 64K-aligned ImageBase", () => {
  const pe = createWindowsLayoutSubject();
  pe.opt.ImageBase = 0x140000000n;

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(pe), []);
});

void test("collectPeHeaderFieldWarnings reports oversized PE32+ SizeOfImage", () => {
  const pe = createWindowsLayoutSubject();
  pe.opt.Magic = PE32_PLUS_OPTIONAL_HEADER_MAGIC;
  pe.opt.SizeOfImage = 0x80000001;

  assert.ok(collectPeHeaderFieldWarnings(pe).includes(
    "PE32+ SizeOfImage exceeds 2 GiB; PE32+ images are documented as limited to a 2 GiB image size."
  ));
});

void test("collectPeHeaderFieldWarnings accepts the PE32+ SizeOfImage limit", () => {
  const pe = createWindowsLayoutSubject();
  pe.opt.Magic = PE32_PLUS_OPTIONAL_HEADER_MAGIC;
  pe.opt.SizeOfImage = 0x80000000;

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(pe), []);
});

void test("collectPeHeaderFieldWarnings reports non-zero Win32VersionValue", () => {
  const pe = createWindowsLayoutSubject();
  pe.opt.Win32VersionValue = 1;

  assert.ok(
    collectPeHeaderFieldWarnings(pe).includes("Win32VersionValue is reserved and must be zero.")
  );
});

void test("collectPeHeaderFieldWarnings accepts zero Win32VersionValue", () => {
  const pe = createWindowsLayoutSubject();
  pe.opt.Win32VersionValue = 0;

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(pe), []);
});

void test("collectPeHeaderFieldWarnings reports non-zero LoaderFlags", () => {
  const pe = createWindowsLayoutSubject();
  pe.opt.LoaderFlags = 1;

  assert.ok(collectPeHeaderFieldWarnings(pe).includes("LoaderFlags is reserved and must be zero."));
});

void test("collectPeHeaderFieldWarnings accepts zero LoaderFlags", () => {
  const pe = createWindowsLayoutSubject();
  pe.opt.LoaderFlags = 0;

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(pe), []);
});

void test("collectPeHeaderFieldWarnings reports reserved DllCharacteristics bits", () => {
  for (const bit of [0x0001, 0x0002, 0x0004, 0x0008]) {
    const pe = createWindowsLayoutSubject();
    pe.opt.DllCharacteristics = bit;
    assert.ok(
      collectPeHeaderFieldWarnings(pe).some(warning =>
        warning.includes(`DllCharacteristics has reserved bits set: 0x${bit.toString(16).padStart(4, "0")}.`)
      )
    );
  }
});

void test("collectPeHeaderFieldWarnings accepts standard DllCharacteristics bits", () => {
  const pe = createWindowsLayoutSubject();
  pe.opt.DllCharacteristics = 0x0100 | 0x0040;

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(pe), []);
});

void test("collectPeHeaderFieldWarnings reports HIGH_ENTROPY_VA on PE32", () => {
  const pe = createWindowsLayoutSubject();
  pe.opt.Magic = PE32_OPTIONAL_HEADER_MAGIC;
  pe.opt.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;

  assert.ok(collectPeHeaderFieldWarnings(pe).includes(
    "HIGH_ENTROPY_VA is set on PE32, but the flag describes support for high-entropy 64-bit virtual address space."
  ));
});

void test("collectPeHeaderFieldWarnings accepts HIGH_ENTROPY_VA on PE32 CLR AnyCPU", () => {
  const pe = createWindowsLayoutSubject();
  pe.opt.Magic = PE32_OPTIONAL_HEADER_MAGIC;
  pe.opt.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
  pe.clr = { Flags: COMIMAGE_FLAGS_ILONLY } as NonNullable<typeof pe.clr>;

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(pe), []);
});

void test("collectPeHeaderFieldWarnings accepts HIGH_ENTROPY_VA on PE32 CLR x86-only IL-only images", () => {
  const pe = createWindowsLayoutSubject();
  pe.opt.Magic = PE32_OPTIONAL_HEADER_MAGIC;
  pe.opt.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
  pe.clr = {
    Flags: COMIMAGE_FLAGS_ILONLY | COMIMAGE_FLAGS_32BITREQUIRED
  } as NonNullable<typeof pe.clr>;

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(pe), []);
});

void test("collectPeHeaderFieldWarnings reports HIGH_ENTROPY_VA on PE32 CLR images without ILONLY", () => {
  const pe = createWindowsLayoutSubject();
  pe.opt.Magic = PE32_OPTIONAL_HEADER_MAGIC;
  pe.opt.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
  pe.clr = {
    Flags: COMIMAGE_FLAGS_32BITREQUIRED
  } as NonNullable<typeof pe.clr>;

  assert.ok(collectPeHeaderFieldWarnings(pe).includes(
    "HIGH_ENTROPY_VA is set on PE32, but the flag describes support for high-entropy 64-bit virtual address space."
  ));
});

void test("collectPeHeaderFieldWarnings accepts HIGH_ENTROPY_VA on PE32+", () => {
  const pe = createWindowsLayoutSubject();
  pe.opt.Magic = PE32_PLUS_OPTIONAL_HEADER_MAGIC;
  pe.opt.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(pe), []);
});

void test("collectPeHeaderFieldWarnings reports deprecated or reserved COFF Characteristics bits", () => {
  for (const bit of [0x0004, 0x0008, 0x0010, 0x0040, 0x0080, 0x8000]) {
    const pe = createWindowsLayoutSubject();
    pe.coff.Characteristics = bit;
    assert.ok(
      collectPeHeaderFieldWarnings(pe).some(warning =>
        warning.includes("COFF Characteristics contains deprecated or reserved bits")
      )
    );
  }
});

void test("collectPeHeaderFieldWarnings accepts standard COFF Characteristics bits", () => {
  const pe = createWindowsLayoutSubject();
  pe.coff.Characteristics = 0x0002 | 0x0020 | 0x2000;

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(pe), []);
});

void test("collectPeHeaderFieldWarnings reports reserved data directory values", () => {
  const pe = createWindowsLayoutSubject();
  pe.dirs = [
    { name: "ARCHITECTURE", rva: 0x1000, size: 0 },
    { name: "GLOBALPTR", rva: 0x2000, size: 4 },
    { name: "RESERVED", rva: 0, size: 8 }
  ];

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(pe), [
    "ARCHITECTURE data directory is reserved and must be zero.",
    "GLOBALPTR data directory Size must be zero.",
    "Reserved data directory is reserved and must be zero."
  ]);
});

void test("collectPeHeaderFieldWarnings accepts a GLOBALPTR RVA with zero Size", () => {
  const pe = createWindowsLayoutSubject();
  pe.dirs = [{ name: "GLOBALPTR", rva: 0x2000, size: 0 }];

  assert.deepStrictEqual(collectPeHeaderFieldWarnings(pe), []);
});
