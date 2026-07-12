"use strict";

import type { PeResources } from "../../analyzers/pe/resources/index.js";
import type { PeInnoSetupFinding } from "../../analyzers/pe/packers/types.js";
import { crc32, u32le } from "./archive-fixture-helpers.js";
import { MockFile } from "../helpers/mock-file.js";

export const INNO_TABLE_OFFSET = 16;
export const INNO_DATA_OFFSET = 80;
export const INNO_HEADER_OFFSET = 120;
export const INNO_ENGINE_OFFSET = 160;
export const INNO_TOTAL_SIZE = 240;
export const INNO_ENGINE_UNPACKED_SIZE = 512;
export const INNO_ENGINE_CRC32 = 0x5c986c33;

const bytesFromHex = (hex: string): Uint8Array =>
  Uint8Array.from(hex.match(/../g) ?? [], byte => Number.parseInt(byte, 16));

const createDecodedEngine = (): Uint8Array => {
  const bytes = new Uint8Array(INNO_ENGINE_UNPACKED_SIZE);
  const view = new DataView(bytes.buffer);
  bytes.set([0x4d, 0x5a]);
  view.setUint32(0x3c, 0x40, true);
  bytes.set([0x50, 0x45, 0, 0], 0x40);
  bytes.set([0xe8, 0x10, 0, 0, 0], 100);
  return bytes;
};

const createCompressedBlock = (): Uint8Array => {
  const packed = bytesFromHex(
    "5d00004000" +
    "0026967c1b8cab3e037bbda36e54430ad74e5407f66d9affffd04f0000"
  );
  const storedSize = Uint32Array.BYTES_PER_ELEMENT + packed.byteLength;
  const headerFields = Uint8Array.of(...u32le(storedSize), 1);
  const block = new Uint8Array(4 + headerFields.byteLength + storedSize);
  block.set(u32le(crc32(headerFields)));
  block.set(headerFields, 4);
  block.set(u32le(crc32(packed)), 9);
  block.set(packed, 13);
  return block;
};

const createOffsetTable = (): Uint8Array => {
  const table = new Uint8Array(44);
  const view = new DataView(table.buffer);
  table.set([0x72, 0x44, 0x6c, 0x50, 0x74, 0x53, 0xcd, 0xe6, 0xd7, 0x7b, 0x0b, 0x2a]);
  view.setUint32(12, 1, true);
  view.setUint32(16, INNO_TOTAL_SIZE, true);
  view.setUint32(20, INNO_ENGINE_OFFSET, true);
  view.setUint32(24, INNO_ENGINE_UNPACKED_SIZE, true);
  view.setUint32(28, INNO_ENGINE_CRC32, true);
  view.setUint32(32, INNO_HEADER_OFFSET, true);
  view.setUint32(36, INNO_DATA_OFFSET, true);
  view.setUint32(40, crc32(table.subarray(0, 40)), true);
  return table;
};

export const createInnoSetupFixture = () => {
  const bytes = new Uint8Array(INNO_TOTAL_SIZE);
  const table = createOffsetTable();
  const block = createCompressedBlock();
  bytes.set(table, INNO_TABLE_OFFSET);
  bytes.set(block, INNO_ENGINE_OFFSET);
  const resources: PeResources = {
    top: [],
    detail: [],
    paths: [{
      nodes: [{ id: 10, name: null }, { id: 11111, name: null }, { id: 0, name: null }],
      size: table.byteLength,
      codePage: 0,
      dataRVA: 0x2000,
      dataFileOffset: INNO_TABLE_OFFSET,
      reserved: 0
    }]
  };
  return {
    block,
    decodedEngine: createDecodedEngine(),
    file: new MockFile(bytes, "inno.exe"),
    resources,
    table
  };
};

export const createInnoFinding = (): PeInnoSetupFinding => ({
  id: "inno-setup",
  name: "Inno Setup installer",
  kind: "installer",
  confidence: "high",
  evidence: ["validated"],
  dataOffset: INNO_DATA_OFFSET,
  headerOffset: INNO_HEADER_OFFSET,
  offsetTableOffset: INNO_TABLE_OFFSET,
  setupExeCrc32: INNO_ENGINE_CRC32,
  setupExeOffset: INNO_ENGINE_OFFSET,
  setupExeStoredSize: createCompressedBlock().byteLength - 9,
  setupExeUnpackedSize: INNO_ENGINE_UNPACKED_SIZE,
  totalSize: INNO_TOTAL_SIZE
});
