"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderSections } from "../../renderers/pe/section-headers.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import { createBasePe, createPeSection } from "../fixtures/pe-renderer-headers-fixture.js";

void test("renderSections omits the section table when no sections exist", () => {
  const pe: PeParseResult = createBasePe();
  const out: string[] = [];

  renderSections(pe, out);

  assert.deepEqual(out, []);
});

void test("renderSections renders regular and COFF string-table section names", () => {
  const pe: PeParseResult = createBasePe();
  pe.sections = [
    createPeSection(".text"),
    createPeSection(".long_section", { coffStringTableOffset: 4, pointerToLinenumbers: 0x220 }),
    createPeSection("", { numberOfLinenumbers: 1 })
  ];

  const out: string[] = [];
  renderSections(pe, out);
  const html = out.join("");

  assert.match(html, /Code \(executable instructions\)/);
  assert.match(html, /COFF name \/4/);
  assert.match(html, /\(unnamed\)/);
  assert.match(html, /LinePtr/);
  assert.match(html, /RelocPtr<\/th><th>Relocs<\/th><th>LinePtr<\/th><th>Lines/);
});

void test("renderSections shows COFF section relocation and line-number metadata", () => {
  const pe: PeParseResult = createBasePe();
  pe.sections = [
    createPeSection(".obj", {
      pointerToRelocations: 0x180,
      pointerToLinenumbers: 0x1a0,
      numberOfRelocations: 3,
      numberOfLinenumbers: 4
    })
  ];

  const out: string[] = [];
  renderSections(pe, out);
  const html = out.join("");

  assert.match(html, /RelocPtr/);
  assert.match(html, /Relocs/);
  assert.match(html, /LinePtr/);
  assert.match(html, /Lines/);
  assert.match(html, /00000180/i);
  assert.match(html, /000001a0/i);
});

void test("renderSections shows raw tail padding status", () => {
  const pe: PeParseResult = createBasePe();
  pe.sections = [
    createPeSection(".zero", {
      virtualSize: 0x100,
      sizeOfRawData: 0x180,
      rawTail: { zeroFilled: true, readableSize: 0x80 }
    }),
    createPeSection(".big", {
      virtualSize: 0x100,
      sizeOfRawData: 0x400,
      rawTail: { zeroFilled: false, readableSize: 0x300 }
    }),
    createPeSection(".trunc", {
      virtualSize: 0x100,
      sizeOfRawData: 0x180,
      rawTail: {
        zeroFilled: null,
        readableSize: 0x40,
        warnings: ["Section raw tail is truncated by end of file; zero-fill status is incomplete."]
      }
    }),
    createPeSection(".plain", { virtualSize: 0x200, sizeOfRawData: 0x200 })
  ];

  const out: string[] = [];
  renderSections(pe, out);
  const html = out.join("");

  assert.match(html, /<th>Padding<\/th>/);
  assert.match(html, /zero-filled/);
  assert.match(html, /contains non-zero bytes/);
  assert.match(html, /does not exceed FileAlignment/);
  assert.match(html, /exceeds FileAlignment/);
  assert.match(html, /unknown zero-fill status; readable 64 B \(64 bytes\)/);
  assert.match(html, /<span class="dim">No<\/span>/);
});
