"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { parseElfTlsInfo } from "../../../../analyzers/elf/tls.js";
import { createElfFile } from "../../../fixtures/elf-sample-file.js";
import { createElfMetadataFile } from "../../../fixtures/elf-metadata-file.js";
import { expectDefined } from "../../../helpers/expect-defined.js";
import { relocationSection } from "../../../fixtures/elf-relocations.js";

void test("parseElfTlsInfo collects PT_TLS segments and TLS sections", async () => {
  const { file } = createElfMetadataFile();
  const parsed = await parseElf(file);
  const elf = expectDefined(parsed);
  const tls = parseElfTlsInfo(elf.programHeaders, elf.sections);
  assert.ok(tls);
  assert.equal(tls.segments.length, 1);
  assert.equal(tls.sections.some(sec => sec.name === ".tdata"), true);
});

void test("parseElfTlsInfo returns null when no TLS is present", async () => {
  const file = createElfFile();
  const parsed = await parseElf(file);
  const elf = expectDefined(parsed);
  assert.equal(parseElfTlsInfo(elf.programHeaders, elf.sections), null);
});

for (const [type, addressDelta, fileDelta, expected] of [
  [1, 0n, 0n, null], [8, 4n, 200n, null],
  [1, -1n, -1n, /file range.*initialization image/],
  [1, 0n, 1n, /file range.*initialization image/],
  [1, 4n, 4n, /file range.*initialization image/],
  [8, 0n, 0n, /zero-filled/], [8, 8n, 0n, /zero-filled/]
] as const) {
  void test(`checks TLS template section type ${type} at ${addressDelta}, file delta ${fileDelta}`, async () => {
    const { file } = createElfMetadataFile();
    const elf = expectDefined(await parseElf(file));
    const segment = expectDefined(elf.programHeaders.find(header => header.type === 7));
    const section = relocationSection(9, { type, flags: 0x402n, size: 4n,
      addr: segment.vaddr + addressDelta, offset: segment.offset + fileDelta });

    const tls = parseElfTlsInfo(elf.programHeaders, [section], elf.header.type);

    assert.deepEqual((tls?.issues ?? []).map(issue => expected?.test(issue)), expected ? [true] : []);
  });
}

void test("keeps an invalid PT_TLS header visible even with a zero memory size", async () => {
  const elf = expectDefined(await parseElf(createElfMetadataFile().file));
  const segment = expectDefined(elf.programHeaders.find(header => header.type === 7));

  const tls = parseElfTlsInfo([{ ...segment, memsz: 0n }], [], elf.header.type);

  assert.equal(tls?.segments.length, 1);
  assert.match(tls?.issues?.join(" ") ?? "", /p_filesz exceeds p_memsz/);
});

void test("requires a template for SHF_TLS in images and accepts TLS sections in relocatable objects", () => {
  const section = relocationSection(9, { type: 8, flags: 0x402n, size: 4n });

  assert.deepEqual(parseElfTlsInfo([], [section], 3)?.issues,
    ["SHF_TLS sections are present without a nonempty PT_TLS template."]);
  assert.equal(parseElfTlsInfo([], [section], 1)?.issues, undefined);
  assert.equal(parseElfTlsInfo([], [{ ...section, name: ".tbss", flags: 0x2n }], 3), null);
});

void test("reports multiple nonempty TLS templates and treats an empty entry as inactive", async () => {
  const elf = expectDefined(await parseElf(createElfMetadataFile().file));
  const segment = expectDefined(elf.programHeaders.find(header => header.type === 7));

  assert.deepEqual(parseElfTlsInfo([segment, { ...segment, index: segment.index + 1 }],
    elf.sections, elf.header.type)?.issues, ["Multiple nonempty PT_TLS entries describe the TLS template."]);
  assert.equal(parseElfTlsInfo([segment, { ...segment, filesz: 0n, memsz: 0n }],
    elf.sections, elf.header.type)?.issues, undefined);
});

void test("matches the entire initialized image and translates a nonzero section offset", async () => {
  const elf = expectDefined(await parseElf(createElfMetadataFile().file));
  const segment = expectDefined(elf.programHeaders.find(header => header.type === 7));
  const template = { ...segment, memsz: segment.filesz };
  const section = relocationSection(9, { name: ".tls_second", flags: 0x402n, size: 2n,
    addr: segment.vaddr + 2n, offset: segment.offset + 2n });

  assert.deepEqual(parseElfTlsInfo([template], [section], 2), {
    segments: [{ index: segment.index, offset: template.offset, vaddr: template.vaddr,
      filesz: template.filesz, memsz: template.memsz, align: template.align }],
    sections: [{ index: section.index, name: ".tls_second", addr: section.addr,
      offset: section.offset, size: section.size, flags: [] }]
  });
});

void test("a template with no zero-filled bytes cannot have a nonempty TLS NOBITS section", async () => {
  const elf = expectDefined(await parseElf(createElfMetadataFile().file));
  const segment = expectDefined(elf.programHeaders.find(header => header.type === 7));
  const template = { ...segment, memsz: segment.filesz };
  const section = relocationSection(9, { type: 8, flags: 0x402n, size: 1n,
    addr: template.vaddr + template.filesz });
  delete section.name;

  const tls = parseElfTlsInfo([template], [section], 2);

  assert.equal(tls?.sections[0]?.name, "");
  assert.deepEqual(tls?.issues, ["TLS section #9 is outside the zero-filled PT_TLS template."]);
});

void test("treats empty TLS entries and malformed geometry as distinct conditions", async () => {
  const elf = expectDefined(await parseElf(createElfMetadataFile().file));
  const segment = expectDefined(elf.programHeaders.find(header => header.type === 7));
  const empty = { ...segment, filesz: 0n, memsz: 0n };
  const impossible = { ...segment, filesz: segment.memsz + 1n };
  const section = relocationSection(9, { flags: 0x402n, size: 1n });

  assert.equal(parseElfTlsInfo([empty], [], 2)?.issues, undefined);
  assert.deepEqual(parseElfTlsInfo([empty], [section], 2)?.issues,
    ["SHF_TLS sections are present without a nonempty PT_TLS template."]);
  assert.deepEqual(parseElfTlsInfo([impossible], [section], 2)?.issues,
    [`PT_TLS #${segment.index}: p_filesz exceeds p_memsz.`]);
  assert.deepEqual(parseElfTlsInfo([{ ...impossible, memsz: 0n }], [section], 2)?.issues,
    [`PT_TLS #${segment.index}: p_filesz exceeds p_memsz.`]);
  assert.equal(parseElfTlsInfo([], [{ ...section, size: 0n }], 2), null);
});

