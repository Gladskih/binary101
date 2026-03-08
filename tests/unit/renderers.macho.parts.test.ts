"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { MachOCodeSignature, MachOFatSlice, MachOSymbol } from "../../analyzers/macho/types.js";
import { createRendererMachOImage } from "../fixtures/macho-renderer-fixture.js";
import { fatSliceCpuLabel, fileTypeLabel, headerCpuLabel, magicLabel } from "../../renderers/macho/header-semantics.js";
import { buildPlatformLabel, buildToolLabel, versionMinLabel } from "../../renderers/macho/version-semantics.js";
import {
  codeDirectoryExecSegLabels,
  codeDirectoryHashLabel,
  codeSignatureBlobLabel,
  pageSizeLabel
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
import { CPU_SUBTYPE_ARM64E, CPU_TYPE_ARM64 } from "../fixtures/macho-thin-sample.js";
import { createMachOIncidentalValues } from "../fixtures/macho-incidental-values.js";

// mach-o/nlist.h ordinals and flags used repeatedly in this file.
const DYNAMIC_LOOKUP_ORDINAL = 0xfe;
const EXECUTABLE_ORDINAL = 0xff;
const N_EXT_BIT = 0x01;
const N_INDR_TYPE = 0x0a;
const N_STAB_MASK = 0xe0;
const N_UNDF_TYPE = 0x00;
const N_WEAK_DEF_BIT = 0x0080;
const N_WEAK_REF_BIT = 0x0040;
const REFERENCED_DYNAMICALLY_BIT = 0x0010;
const SELF_LIBRARY_ORDINAL = 0x00;
// xnu/osfmk/kern/cs_blobs.h: CSMAGIC_CODEDIRECTORY.
const CODEDIRECTORY_MAGIC = 0xfade0c02;

void test("Mach-O renderer semantics expose fallback labels", () => {
  const image = createRendererMachOImage();
  const slice: MachOFatSlice = {
    index: 0,
    cputype: CPU_TYPE_ARM64,
    cpusubtype: CPU_SUBTYPE_ARM64E,
    offset: 0x1000,
    size: 0x2000,
    align: 12,
    reserved: null,
    image: null,
    issues: []
  };
  assert.equal(magicLabel(0xfeedfacf), "MH_MAGIC_64");
  assert.equal(magicLabel(0xcffaedfe), "MH_CIGAM_64");
  // Not a known Mach-O magic.
  assert.equal(magicLabel(0xdeadbeef), "0xdeadbeef");
  assert.equal(fileTypeLabel(6), "Dynamic library");
  // Not present in fileTypeNames.
  assert.equal(fileTypeLabel(0xffff), "0xffff");
  assert.equal(headerCpuLabel(image.header), "ARM64 (arm64e)");
  assert.equal(fatSliceCpuLabel(slice), "ARM64 (arm64e)");
  assert.equal(buildPlatformLabel(11), "visionOS");
  // platformNames only defines the currently known platform IDs 0..12.
  assert.equal(buildPlatformLabel(0xff), "platform 0xff");
  assert.equal(buildToolLabel(1024), "metal");
  // buildToolNames only defines 1..4 and 1024.
  assert.equal(buildToolLabel(0xff), "0xff");
  assert.equal(versionMinLabel(0x30), "watchOS"); // LC_VERSION_MIN_WATCHOS
  assert.equal(codeSignatureBlobLabel(null), "Unknown");
  assert.equal(codeSignatureBlobLabel(CODEDIRECTORY_MAGIC), "CodeDirectory");
  assert.equal(codeDirectoryHashLabel(99), "hash 99");
  assert.deepEqual(codeDirectoryExecSegLabels(null), []);
  assert.equal(pageSizeLabel(0), "Infinite");
  assert.equal(pageSizeLabel(12), "4 KB (4096 bytes)");
  assert.match(formatByteSize(0x100000000), /4294967296 bytes/);
});

void test("Mach-O symbol semantics and symbol view cover bindings, descriptions, and summaries", () => {
  const values = createMachOIncidentalValues();
  const image = createRendererMachOImage();
  const symbols: MachOSymbol[] = [
    {
      index: 0,
      name: "_local",
      stringIndex: values.nextUint8(),
      type: 0x0e,
      sectionIndex: 1,
      description: 0,
      libraryOrdinal: null,
      value: BigInt(values.nextUint16() + 0x1000)
    },
    {
      index: 1,
      name: "_lazy",
      stringIndex: values.nextUint8(),
      type: N_EXT_BIT | N_UNDF_TYPE,
      sectionIndex: 0,
      description: 1 | REFERENCED_DYNAMICALLY_BIT | N_WEAK_REF_BIT,
      libraryOrdinal: 1,
      value: 0n
    },
    {
      index: 2,
      name: "_weak",
      stringIndex: values.nextUint8(),
      type: N_EXT_BIT | N_UNDF_TYPE,
      sectionIndex: 0,
      description: 5 | N_WEAK_DEF_BIT,
      libraryOrdinal: EXECUTABLE_ORDINAL,
      value: 0n
    },
    {
      index: 3,
      name: "_lookup",
      stringIndex: values.nextUint8(),
      type: N_EXT_BIT | N_INDR_TYPE,
      sectionIndex: 0,
      description: 0,
      libraryOrdinal: DYNAMIC_LOOKUP_ORDINAL,
      value: 0n
    },
    {
      index: 4,
      name: "_debug",
      stringIndex: values.nextUint8(),
      type: N_STAB_MASK,
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
  assert.deepEqual(symbolBindingLabels(image, {
    ...symbols[0]!,
    index: 7,
    name: "_localWithFlagBits",
    // High-byte n_desc flag bits must not be treated as a dylib ordinal for locals.
    description: 0x0100,
    libraryOrdinal: 1
  }), ["local"]);
  assert.deepEqual(symbolBindingLabels(image, {
    ...symbols[0]!,
    index: 6,
    name: "_self",
    type: N_EXT_BIT | 0x0e,
    libraryOrdinal: SELF_LIBRARY_ORDINAL
  }), ["external", "This image"]);
  assert.deepEqual(symbolBindingLabels(image, symbols[3]!), ["external", "Dylib #254"]);
  assert.deepEqual(symbolBindingLabels(image, {
    ...symbols[1]!,
    index: 5,
    name: "_flat",
    description: 0,
    libraryOrdinal: DYNAMIC_LOOKUP_ORDINAL
  }), ["external", "Dynamic lookup"]);
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
  assert.match(html, /Dylib #254/);
  assert.match(html, /Debug \/ STAB/);

  image.dylibs = Array.from({ length: DYNAMIC_LOOKUP_ORDINAL }, (_, index) => ({
    loadCommandIndex: index,
    command: 0,
    name: `/usr/lib/lib${index}.dylib`,
    timestamp: 0,
    currentVersion: 0,
    compatibilityVersion: 0
  }));
  assert.deepEqual(symbolBindingLabels(image, symbols[3]!), ["external", "/usr/lib/lib253.dylib"]);

  const objectImage = {
    ...image,
    header: {
      ...image.header,
      filetype: 1
    }
  };
  assert.deepEqual(symbolBindingLabels(objectImage, {
    ...symbols[0]!,
    index: 8,
    name: "_resolver",
    type: N_EXT_BIT | 0x0e,
    // High-byte n_desc flag bits are object-file flags for MH_OBJECT.
    description: 0x0100,
    libraryOrdinal: 1
  }), ["external"]);
});

void test("Mach-O code-signing view renders full and sparse signatures", () => {
  const values = createMachOIncidentalValues();
  const fullSignature: MachOCodeSignature = {
    loadCommandIndex: 0,
    dataoff: 0x2800,
    datasize: 0x80,
    magic: CODEDIRECTORY_MAGIC,
    length: 0x60,
    blobCount: 2,
    slots: [
      { type: 0, offset: 0x10, magic: CODEDIRECTORY_MAGIC, length: 0x60 },
      { type: 0x10000, offset: 0x70, magic: null, length: null }
    ],
    codeDirectory: {
      version: 0x20500,
      flags: 0x10000,
      hashSize: 32,
      hashType: 99,
      platform: 11,
      pageSizeShift: 0,
      nSpecialSlots: 2,
      nCodeSlots: 4,
      codeLimit: 0x2000n,
      identifier: values.nextLabel("com.example.binary101"),
      teamIdentifier: values.nextLabel("TEAMID"),
      execSegBase: 0x1000n,
      execSegLimit: 0x2000n,
      execSegFlags: 0x1n,
      runtime: 1
    },
    issues: []
  };
  const fullHtml = renderCodeSignature(fullSignature);
  assert.match(fullHtml, new RegExp(fullSignature.codeDirectory?.teamIdentifier ?? ""));
  assert.match(fullHtml, /Exec segment flags/);
  assert.match(fullHtml, /Page size/);
  assert.match(fullHtml, /Infinite/);
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
