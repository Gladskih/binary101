"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  CSMAGIC_CODEDIRECTORY,
  DYNAMIC_LOOKUP_ORDINAL,
  EXECUTABLE_ORDINAL,
  LC_VERSION_MIN_WATCHOS,
  N_EXT,
  N_INDR,
  N_STAB,
  N_UNDF,
  N_WEAK_DEF,
  N_WEAK_REF,
  REFERENCED_DYNAMICALLY
} from "../../analyzers/macho/commands.js";
import type { MachOCodeSignature, MachOFatSlice, MachOParseResult, MachOSymbol } from "../../analyzers/macho/types.js";
import { createRendererMachOImage } from "../fixtures/macho-renderer-fixture.js";
import { renderFat } from "../../renderers/macho/fat-view.js";
import { fatSliceCpuLabel, fileTypeLabel, headerCpuLabel, magicLabel } from "../../renderers/macho/header-semantics.js";
import { renderImage } from "../../renderers/macho/image-view.js";
import { renderMachO } from "../../renderers/macho/index.js";
import { buildPlatformLabel, buildToolLabel, versionMinLabel } from "../../renderers/macho/version-semantics.js";
import {
  codeDirectoryExecSegLabels,
  codeDirectoryHashLabel,
  codeSignatureBlobLabel,
  pageSizeBytes
} from "../../renderers/macho/codesign-semantics.js";
import { renderCodeSignature } from "../../renderers/macho/codesign-view.js";
import {
  sectionNameByIndex,
  summarizeSymbols,
  symbolBindingLabels,
  symbolDescriptionLabels,
  symbolTypeLabelFor
} from "../../renderers/macho/symbol-semantics.js";
import { renderSymtab } from "../../renderers/macho/symbols-view.js";
import { formatByteSize } from "../../renderers/macho/value-format.js";

void test("Mach-O renderer semantics expose fallback labels", () => {
  const image = createRendererMachOImage();
  const slice: MachOFatSlice = {
    index: 0,
    cputype: 0x0100000c,
    cpusubtype: 2,
    offset: 0x1000,
    size: 0x2000,
    align: 12,
    reserved: null,
    image: null,
    issues: []
  };
  assert.equal(magicLabel(0xfeedfacf), "MH_MAGIC_64");
  assert.equal(magicLabel(0xdeadbeef), "0xdeadbeef");
  assert.equal(fileTypeLabel(6), "Dynamic library");
  assert.equal(fileTypeLabel(0xffff), "0xffff");
  assert.equal(headerCpuLabel(image.header), "ARM64 (arm64e)");
  assert.equal(fatSliceCpuLabel(slice), "ARM64 (arm64e)");
  assert.equal(buildPlatformLabel(11), "visionOS");
  assert.equal(buildPlatformLabel(0xff), "platform 0xff");
  assert.equal(buildToolLabel(1024), "metal");
  assert.equal(buildToolLabel(0xff), "0xff");
  assert.equal(versionMinLabel(LC_VERSION_MIN_WATCHOS), "watchOS");
  assert.equal(codeSignatureBlobLabel(null), "Unknown");
  assert.equal(codeSignatureBlobLabel(CSMAGIC_CODEDIRECTORY), "CodeDirectory");
  assert.equal(codeDirectoryHashLabel(99), "hash 99");
  assert.deepEqual(codeDirectoryExecSegLabels(null), []);
  assert.equal(pageSizeBytes(0), null);
  assert.equal(pageSizeBytes(12), 4096);
  assert.match(formatByteSize(0x100000000), /4294967296 bytes/);
});

void test("Mach-O symbol semantics and symbol view cover bindings, descriptions, and summaries", () => {
  const image = createRendererMachOImage();
  const symbols: MachOSymbol[] = [
    {
      index: 0,
      name: "_local",
      stringIndex: 1,
      type: 0x0e,
      sectionIndex: 1,
      description: 0,
      libraryOrdinal: null,
      value: 0x1000n
    },
    {
      index: 1,
      name: "_lazy",
      stringIndex: 8,
      type: N_EXT | N_UNDF,
      sectionIndex: 0,
      description: 1 | REFERENCED_DYNAMICALLY | N_WEAK_REF,
      libraryOrdinal: 1,
      value: 0n
    },
    {
      index: 2,
      name: "_weak",
      stringIndex: 14,
      type: N_EXT | N_UNDF,
      sectionIndex: 0,
      description: 5 | N_WEAK_DEF,
      libraryOrdinal: EXECUTABLE_ORDINAL,
      value: 0n
    },
    {
      index: 3,
      name: "_lookup",
      stringIndex: 20,
      type: N_EXT | N_INDR,
      sectionIndex: 0,
      description: 0,
      libraryOrdinal: DYNAMIC_LOOKUP_ORDINAL,
      value: 0n
    },
    {
      index: 4,
      name: "_debug",
      stringIndex: 28,
      type: N_STAB,
      sectionIndex: 0,
      description: 0,
      libraryOrdinal: null,
      value: 0n
    }
  ];
  image.symtab = {
    symoff: 0x200,
    nsyms: symbols.length,
    stroff: 0x280,
    strsize: 0x40,
    symbols,
    issues: []
  };

  assert.equal(sectionNameByIndex(image, 1), "__text");
  assert.equal(sectionNameByIndex(image, 99), null);
  assert.equal(symbolTypeLabelFor(symbols[4]!), "Debug / STAB");
  assert.deepEqual(symbolDescriptionLabels(symbols[1]!), [
    "Undefined (lazy)",
    "Referenced dynamically",
    "Weak reference"
  ]);
  assert.deepEqual(symbolDescriptionLabels(symbols[2]!), ["Private undefined (lazy)", "Reference to weak symbol"]);
  assert.deepEqual(symbolBindingLabels(image, symbols[0]!), ["local"]);
  assert.deepEqual(symbolBindingLabels(image, symbols[3]!), ["external", "Dynamic lookup"]);
  assert.deepEqual(summarizeSymbols(symbols), {
    debug: 1,
    externalDefined: 0,
    indirect: 1,
    local: 1,
    undefined: 2
  });

  const html = renderSymtab(image);
  assert.match(html, /Show symbols \(5\)/);
  assert.match(html, /Main executable/);
  assert.match(html, /Dynamic lookup/);
  assert.match(html, /Debug \/ STAB/);
});

void test("Mach-O code-signing view renders full and sparse signatures", () => {
  const fullSignature: MachOCodeSignature = {
    loadCommandIndex: 0,
    dataoff: 0x2800,
    datasize: 0x80,
    magic: CSMAGIC_CODEDIRECTORY,
    length: 0x60,
    blobCount: 2,
    slots: [
      { type: 0, offset: 0x10, magic: CSMAGIC_CODEDIRECTORY, length: 0x60 },
      { type: 0x10000, offset: 0x70, magic: null, length: null }
    ],
    codeDirectory: {
      version: 0x20500,
      flags: 0x10000,
      hashSize: 32,
      hashType: 99,
      platform: 11,
      pageSizeShift: 12,
      nSpecialSlots: 2,
      nCodeSlots: 4,
      codeLimit: 0x2000n,
      identifier: "com.example.binary101",
      teamIdentifier: "TEAMID",
      execSegBase: 0x1000n,
      execSegLimit: 0x2000n,
      execSegFlags: 0x1n,
      runtime: 1
    },
    issues: []
  };
  const fullHtml = renderCodeSignature(fullSignature);
  assert.match(fullHtml, /TEAMID/);
  assert.match(fullHtml, /Exec segment flags/);
  assert.match(fullHtml, /Page size/);
  assert.match(fullHtml, /hash 99/);

  const sparseHtml = renderCodeSignature({
    ...fullSignature,
    blobCount: null,
    slots: [],
    codeDirectory: null,
    magic: null
  });
  assert.doesNotMatch(sparseHtml, /Indexed blobs/);
  assert.doesNotMatch(sparseHtml, /Page size/);
});

void test("Mach-O image and fat renderers cover optional metadata, notices, and slice fallbacks", () => {
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
        cputype: 0x01000007,
        cpusubtype: 3,
        offset: 0x1000,
        size: 0x1000,
        align: 12,
        reserved: 0x1234,
        image,
        issues: []
      },
      {
        index: 1,
        cputype: 0x0100000c,
        cpusubtype: 2,
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
