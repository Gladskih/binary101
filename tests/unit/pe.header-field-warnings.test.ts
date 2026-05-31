"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { collectPeHeaderFieldWarnings } from "../../analyzers/pe/layout/header-field-warnings.js";
import { createWindowsLayoutSubject } from "../fixtures/pe-layout-warning-subject.js";

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
