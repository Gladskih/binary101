"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { MachOParseResult } from "../../analyzers/macho/types.js";
import { renderFat } from "../../renderers/macho/fat-view.js";
import { renderImage } from "../../renderers/macho/image-view.js";
import { renderMachO } from "../../renderers/macho/index.js";
import { createRendererMachOImage } from "../fixtures/macho-renderer-fixture.js";
import { CPU_SUBTYPE_ARM64E, CPU_SUBTYPE_X86_64_ALL, CPU_TYPE_ARM64, CPU_TYPE_X86_64 } from "../fixtures/macho-thin-sample.js";
import { createMachOIncidentalValues } from "../fixtures/macho-incidental-values.js";

// mach-o/nlist.h: N_EXT == 0x01 and SELF_LIBRARY_ORDINAL == 0x00.
const N_EXT_BIT = 0x01;
const SELF_LIBRARY_ORDINAL = 0x00;
// xnu/osfmk/kern/cs_blobs.h: CSMAGIC_CODEDIRECTORY.
const CODEDIRECTORY_MAGIC = 0xfade0c02;

void test("Mach-O image and fat renderers cover optional metadata, notices, and slice fallbacks", () => {
  const values = createMachOIncidentalValues();
  const image = createRendererMachOImage();
  const imageHtml = renderImage(image);
  assert.match(imageHtml, /Build metadata/);
  assert.match(imageHtml, /Not mapped by parsed segments/);
  assert.match(imageHtml, /Install name/);
  assert.match(imageHtml, /RPATHs/);
  assert.match(imageHtml, /Extra loader metadata/);
  assert.match(imageHtml, /Fileset entry/);
  assert.match(imageHtml, /Notices/);

  const fatResult: MachOParseResult = {
    kind: "fat",
    fileSize: 0x4000,
    image: null,
    fatHeader: null,
    slices: [
      {
        index: 0,
        cputype: CPU_TYPE_X86_64,
        cpusubtype: CPU_SUBTYPE_X86_64_ALL,
        offset: 0x1000,
        size: 0x1000,
        align: 12,
        reserved: values.nextUint16(),
        image,
        issues: []
      },
      {
        index: 1,
        cputype: CPU_TYPE_ARM64,
        cpusubtype: CPU_SUBTYPE_ARM64E,
        offset: 0x2000,
        size: 0x1000,
        align: 12,
        reserved: null,
        image: null,
        issues: ["slice is truncated"]
      }
    ],
    issues: ["universal wrapper is truncated"]
  };

  const fatHtml = renderFat(fatResult);
  assert.match(fatHtml, /slice is truncated/);
  assert.match(fatHtml, /Reserved/);

  const html = renderMachO(fatResult);
  assert.match(html, /universal wrapper is truncated/);
});

void test("Mach-O image rendering keeps file offsets absolute for fat slices", () => {
  const values = createMachOIncidentalValues();
  const image = createRendererMachOImage();
  image.offset = 0x1000;
  const symbolCount = 1;
  const symbolTableOffset = 0x200;
  const stringTableOffset = 0x280;
  const stringTableSize = 0x20;
  const codeSignatureOffset = 0x2800;
  const codeSignatureSize = 0x80;
  const encryptedRangeOffset = 0x200;
  const encryptedRangeSize = 0x40;
  const entryPointLabel = values.nextLabel("kernelcache");
  image.symtab = {
    symoff: symbolTableOffset,
    nsyms: symbolCount,
    stroff: stringTableOffset,
    strsize: stringTableSize,
    symbols: [{
      index: 0,
      name: "_main",
      stringIndex: 1,
      type: N_EXT_BIT | 0x0e,
      sectionIndex: 1,
      description: 0,
      libraryOrdinal: SELF_LIBRARY_ORDINAL,
      value: 0x1000n
    }],
    issues: []
  };
  image.codeSignature = {
    loadCommandIndex: 0,
    dataoff: codeSignatureOffset,
    datasize: codeSignatureSize,
    magic: CODEDIRECTORY_MAGIC,
    length: 0x60,
    blobCount: null,
    slots: [],
    codeDirectory: null,
    issues: []
  };
  image.encryptionInfos[0] = {
    ...image.encryptionInfos[0]!,
    cryptoff: encryptedRangeOffset,
    cryptsize: encryptedRangeSize,
    cryptid: 1
  };
  image.fileSetEntries[0] = {
    ...image.fileSetEntries[0]!,
    entryId: entryPointLabel,
    fileoff: BigInt(symbolTableOffset)
  };

  const html = renderImage(image);

  assert.match(html, /1 entries @ 0x1200/);
  assert.match(html, /32 B \(32 bytes\) @ 0x1280/);
  assert.match(html, /CodeDirectory @ 0x3800/);
  assert.match(html, /0x3800 \+ 128 B \(128 bytes\)/);
  assert.match(html, /0x1200 \+ 64 B \(64 bytes\).*cryptid 1/);
  assert.match(html, new RegExp(`${entryPointLabel}.*@ 0x1200`));
});
