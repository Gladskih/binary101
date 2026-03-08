"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseMachO } from "../../analyzers/macho/index.js";
import type { MachOParseResult } from "../../analyzers/macho/types.js";
import { renderMachO } from "../../renderers/macho/index.js";
import { createMachOFile, createMachOUniversalFile } from "../fixtures/macho-fixtures.js";
import { CPU_SUBTYPE_X86_64_ALL, CPU_TYPE_X86_64 } from "../fixtures/macho-thin-sample.js";

void test("renderMachO renders rich thin binaries from raw analyzer fields", async () => {
  const parsed = await parseMachO(createMachOFile());
  assert.ok(parsed);
  const html = renderMachO(parsed);
  assert.match(html, /Source version 13\.0\.2\.1\.5/);
  assert.match(html, /LC_LOAD_DYLINKER/);
  assert.match(html, /\/usr\/lib\/dyld/);
  assert.match(html, /Code signing/);
});

void test("renderMachO renders sparse thin binaries without optional sections", () => {
  const parsed: MachOParseResult = {
    kind: "thin",
    fileSize: 0x1000,
    image: {
      offset: 0,
      size: 0x1000,
      header: {
        magic: 0xfeedfacf, // MH_MAGIC_64
        is64: true,
        littleEndian: true,
        cputype: CPU_TYPE_X86_64,
        cpusubtype: CPU_SUBTYPE_X86_64_ALL,
        filetype: 0x2,
        ncmds: 0,
        sizeofcmds: 0,
        flags: 0,
        reserved: 0
      },
      loadCommands: [],
      segments: [],
      dylibs: [],
      idDylib: null,
      rpaths: [],
      stringCommands: [],
      uuid: null,
      buildVersions: [],
      minVersions: [],
      sourceVersion: null,
      entryPoint: null,
      dyldInfo: null,
      linkeditData: [],
      encryptionInfos: [],
      fileSetEntries: [],
      symtab: null,
      codeSignature: null,
      issues: []
    },
    fatHeader: null,
    slices: [],
    issues: []
  };
  const html = renderMachO(parsed);
  assert.match(html, /Mach-O header/);
  assert.doesNotMatch(html, /Code signing/);
  assert.doesNotMatch(html, /Load commands/);
});

void test("renderMachO renders universal binaries from raw slice fields", async () => {
  const parsed = await parseMachO(createMachOUniversalFile());
  assert.ok(parsed);
  const html = renderMachO(parsed);
  assert.match(html, /Universal binary/);
  assert.match(html, /ARM64 \(arm64e\)/);
});
