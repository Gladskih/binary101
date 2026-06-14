"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { LC_SYMTAB, LC_UUID, MH_MAGIC_64 } from "../../analyzers/macho/commands.js";
import { collectThinLoadCommands } from "../../analyzers/macho/thin-load-command-collection.js";
import { applyThinLoadCommand } from "../../analyzers/macho/thin-load-command-dispatch.js";
import {
  buildThinImage,
  createThinLoadCommandState
} from "../../analyzers/macho/thin-load-command-state.js";
import { parseThinExternalData } from "../../analyzers/macho/thin-external-data.js";
import type { MachOFileHeader } from "../../analyzers/macho/types.js";

const THIN_HEADER_SIZE = 32;

void test("createThinLoadCommandState starts with empty command collections", () => {
  const state = createThinLoadCommandState();
  assert.deepEqual(state.loadCommands, []);
  assert.deepEqual(state.segments, []);
  assert.equal(state.idDylib, null);
  assert.equal(state.nextSectionIndex.value, 1);
  assert.equal(state.seenSingletonCommands.size, 0);
});

void test("applyThinLoadCommand records UUID command payloads", () => {
  const view = new DataView(new ArrayBuffer(24));
  for (let index = 0; index < 16; index += 1) view.setUint8(8 + index, index);
  const state = createThinLoadCommandState();
  const issues: string[] = [];
  applyThinLoadCommand(view, LC_UUID, 2, true, state, issues);
  assert.equal(state.uuid, "00010203-0405-0607-0809-0a0b0c0d0e0f");
  assert.deepEqual(issues, []);
});

void test("applyThinLoadCommand warns instead of throwing for truncated symbol tables", () => {
  const state = createThinLoadCommandState();
  const issues: string[] = [];
  applyThinLoadCommand(new DataView(new ArrayBuffer(16)), LC_SYMTAB, 3, true, state, issues);
  assert.equal(state.symtabCommand, null);
  assert.match(issues.join("\n"), /symbol-table command is truncated/);
});

void test("collectThinLoadCommands records invalid command headers before stopping", async () => {
  const bytes = new Uint8Array(THIN_HEADER_SIZE + 8);
  const view = new DataView(bytes.buffer);
  view.setUint32(THIN_HEADER_SIZE, LC_UUID, true);
  view.setUint32(THIN_HEADER_SIZE + 4, 4, true);
  const state = createThinLoadCommandState();
  const issues: string[] = [];
  await collectThinLoadCommands(
    createMemoryRangeReader(bytes),
    0,
    THIN_HEADER_SIZE,
    createHeader(1),
    bytes.length,
    state,
    issues
  );
  assert.equal(state.loadCommands.length, 1);
  assert.equal(state.uuid, null);
  assert.match(issues.join("\n"), /invalid cmdsize 4/);
});

void test("parseThinExternalData normalizes entry points without linked ranges", async () => {
  const state = createThinLoadCommandState();
  state.entryPoint = { loadCommandIndex: 4, entryoff: 0x20n, stacksize: 0n };
  const issues: string[] = [];
  const externalData = await parseThinExternalData(
    new File([new Uint8Array(0)], "empty-macho"),
    0,
    0,
    createHeader(0),
    state,
    issues
  );
  assert.deepEqual(externalData, { symtab: null, codeSignature: null });
  assert.deepEqual(state.entryPoint, { loadCommandIndex: 4, entryoff: 0x20n, stacksize: 0n });
  assert.deepEqual(issues, []);
});

void test("buildThinImage preserves collected command data", () => {
  const state = createThinLoadCommandState();
  state.entryPoint = { loadCommandIndex: 5, entryoff: 0x40n, stacksize: 0n };
  const image = buildThinImage(0, THIN_HEADER_SIZE, createHeader(0), state, {
    symtab: null,
    codeSignature: null
  }, ["kept"]);
  assert.equal(image.header.magic, MH_MAGIC_64);
  assert.deepEqual(image.issues, ["kept"]);
  assert.deepEqual(image.entryPoint, { loadCommandIndex: 5, entryoff: 0x40n, stacksize: 0n });
});

const createMemoryRangeReader = (bytes: Uint8Array) => ({
  read: async (offset: number, size: number): Promise<DataView> =>
    new DataView(bytes.buffer, bytes.byteOffset + offset, Math.min(size, bytes.length - offset)),
  readZeroTerminatedString: async (): Promise<string> => ""
});

const createHeader = (ncmds: number): MachOFileHeader => ({
  magic: MH_MAGIC_64,
  is64: true,
  littleEndian: true,
  cputype: 0,
  cpusubtype: 0,
  filetype: 0,
  ncmds,
  sizeofcmds: 0,
  flags: 0,
  reserved: 0
});
