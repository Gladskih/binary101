"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseThinImage } from "../../analyzers/macho/thin.js";
import { CPU_SUBTYPE_X86_64_ALL, CPU_TYPE_X86_64 } from "../fixtures/macho-thin-sample.js";
import { createThinMachOFixtureData, wrapMachOBytes } from "../fixtures/macho-fixtures.js";
import { createMachOIncidentalValues } from "../fixtures/macho-incidental-values.js";

const THIN_HEADER_SIZE = 32;
const textEncoder = new TextEncoder();

const createThinImageWithCommands = (...commands: Uint8Array[]): Uint8Array => {
  const loadCommandBytes = commands.reduce((sum, command) => sum + command.length, 0);
  const bytes = new Uint8Array(THIN_HEADER_SIZE + loadCommandBytes);
  const view = new DataView(bytes.buffer);
  // mach-o/loader.h: MH_CIGAM_64 == 0xcffaedfe.
  view.setUint32(0, 0xcffaedfe, false);
  view.setUint32(4, CPU_TYPE_X86_64, true);
  view.setUint32(8, CPU_SUBTYPE_X86_64_ALL, true);
  // mach-o/loader.h: MH_EXECUTE == 0x2.
  view.setUint32(12, 0x2, true);
  view.setUint32(16, commands.length, true);
  view.setUint32(20, loadCommandBytes, true);
  let cursor = THIN_HEADER_SIZE;
  for (const command of commands) {
    bytes.set(command, cursor);
    cursor += command.length;
  }
  return bytes;
};

const createLoadCommand = (cmd: number, payloadSize: number): Uint8Array => {
  const bytes = new Uint8Array(Math.ceil((8 + payloadSize) / 8) * 8);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, cmd, true);
  view.setUint32(4, bytes.length, true);
  return bytes;
};

void test("parseThinImage reports segment and section ranges that extend past the Mach-O image", async () => {
  const fixture = createThinMachOFixtureData();
  const values = createMachOIncidentalValues();
  const bytes = fixture.bytes.slice();
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const textSectionOffset = fixture.layout.textSegmentCommandOffset + 72;
  view.setBigUint64(
    fixture.layout.textSegmentCommandOffset + 48,
    BigInt(bytes.length + 1),
    true
  );
  view.setBigUint64(textSectionOffset + 40, BigInt((values.nextUint8() & 0x1f) + 0x10), true);
  view.setUint32(textSectionOffset + 48, bytes.length - 4, true);
  view.setUint32(textSectionOffset + 56, bytes.length - 4, true);
  view.setUint32(textSectionOffset + 60, 1, true);

  const parsed = await parseThinImage(wrapMachOBytes(bytes, "thin-bad-ranges"), 0, bytes.length);

  assert.ok(parsed);
  assert.match(parsed.issues.join("\n"), /segment __TEXT file range .* extends beyond the Mach-O image/i);
  assert.match(parsed.issues.join("\n"), /section __TEXT,__text data range .* extends beyond the Mach-O image/i);
  assert.match(parsed.issues.join("\n"), /section __TEXT,__text relocation range .* extends beyond the Mach-O image/i);
});

void test("parseThinImage reports sections that extend beyond their owning segment ranges", async () => {
  const fixture = createThinMachOFixtureData();
  const baseline = await parseThinImage(wrapMachOBytes(fixture.bytes, "thin-section-baseline"), 0, fixture.bytes.length);
  assert.ok(baseline);
  const textSegment = baseline.segments.find(segment => segment.name === "__TEXT");
  assert.ok(textSegment);
  const textSection = textSegment.sections.find(section => section.sectionName === "__text");
  assert.ok(textSection);
  const bytes = fixture.bytes.slice();
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // segment_command_64.vmsize and filesize sit at offsets 32 and 48 within
  // the load command. Shrinking them to the section start keeps the image
  // valid while making the existing section lie just outside the segment.
  view.setBigUint64(
    fixture.layout.textSegmentCommandOffset + 32,
    textSection.addr - textSegment.vmaddr,
    true
  );
  view.setBigUint64(
    fixture.layout.textSegmentCommandOffset + 48,
    BigInt(textSection.offset) - textSegment.fileoff,
    true
  );

  const parsed = await parseThinImage(wrapMachOBytes(bytes, "thin-section-outside-segment"), 0, bytes.length);

  assert.ok(parsed);
  assert.match(parsed.issues.join("\n"), /section __TEXT,__text file range .* extends beyond segment __TEXT file range/i);
  assert.match(parsed.issues.join("\n"), /section __TEXT,__text VM range .* extends beyond segment __TEXT VM range/i);
});

void test("parseThinImage reports dyld, linkedit, encryption, and fileset ranges that extend past the Mach-O image", async () => {
  const values = createMachOIncidentalValues();
  const dyldDataOffset = values.nextUint8() + 1;
  const exportsTrieOffset = dyldDataOffset + values.nextUint8() + 1;
  const encryptedRangeOffset = exportsTrieOffset + values.nextUint8() + 1;
  const filesetEntryOffset = encryptedRangeOffset + values.nextUint8() + 1;
  // mach-o/loader.h: LC_DYLD_INFO_ONLY == 0x80000022.
  const dyldInfoCommand = createLoadCommand(0x80000022, 40);
  const dyldInfoView = new DataView(dyldInfoCommand.buffer);
  // mach-o/loader.h: LC_DYLD_EXPORTS_TRIE == 0x80000033.
  const exportsTrieCommand = createLoadCommand(0x80000033, 8);
  const exportsTrieView = new DataView(exportsTrieCommand.buffer);
  // mach-o/loader.h: LC_ENCRYPTION_INFO_64 == 0x2c.
  const encryptionCommand = createLoadCommand(0x2c, 16);
  const encryptionView = new DataView(encryptionCommand.buffer);
  const filesetEntryBytes = textEncoder.encode(`${values.nextLabel("com.example.slice")}\0`);
  // mach-o/loader.h: LC_FILESET_ENTRY == 0x80000035.
  const filesetEntryCommand = createLoadCommand(0x80000035, 32 + filesetEntryBytes.length);
  const filesetEntryView = new DataView(filesetEntryCommand.buffer);
  const imageSize =
    THIN_HEADER_SIZE +
    dyldInfoCommand.length +
    exportsTrieCommand.length +
    encryptionCommand.length +
    filesetEntryCommand.length;
  dyldInfoView.setUint32(8, imageSize + dyldDataOffset, true);
  dyldInfoView.setUint32(12, (values.nextUint8() & 0x1f) + 0x10, true);
  exportsTrieView.setUint32(8, imageSize + exportsTrieOffset, true);
  exportsTrieView.setUint32(12, (values.nextUint8() & 0x1f) + 0x20, true);
  encryptionView.setUint32(8, imageSize + encryptedRangeOffset, true);
  encryptionView.setUint32(12, (values.nextUint8() & 0x1f) + 0x20, true);
  encryptionView.setUint32(16, 1, true);
  filesetEntryView.setBigUint64(8, BigInt(values.nextUint16() + 1), true);
  filesetEntryView.setBigUint64(16, BigInt(imageSize + filesetEntryOffset), true);
  filesetEntryView.setUint32(24, 32, true);
  filesetEntryCommand.set(filesetEntryBytes, 32);

  const bytes = createThinImageWithCommands(
    dyldInfoCommand, exportsTrieCommand, encryptionCommand, filesetEntryCommand
  );
  const parsed = await parseThinImage(wrapMachOBytes(bytes, "thin-bad-linkedit-ranges"), 0, bytes.length);

  assert.ok(parsed);
  assert.match(parsed.issues.join("\n"), /LC_DYLD_INFO_ONLY rebase data range .* extends beyond the Mach-O image/i);
  assert.match(parsed.issues.join("\n"), /LC_DYLD_EXPORTS_TRIE data range .* extends beyond the Mach-O image/i);
  assert.match(parsed.issues.join("\n"), /LC_ENCRYPTION_INFO_64 encrypted range .* extends beyond the Mach-O image/i);
  assert.match(parsed.issues.join("\n"), /fileset entry .* file offset .* points outside the Mach-O image/i);
});
