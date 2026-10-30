import type { WasmReader } from "./reader.js";
import { readHeapType, readValueType, VALUE_TYPES } from "./value-types.js";

// Immediate layouts: https://webassembly.github.io/spec/core/binary/instructions.html
export const readMemoryArgument = async (reader: WasmReader): Promise<string> => {
  const flags = await reader.u32();
  if (flags > 127) throw new Error("Invalid memory alignment flags");
  const memory = flags & 64 ? await reader.u32() : 0;
  return `memory=${memory} align=2^${flags & 63} offset=${await reader.unsigned(64)}`;
};

const readFloat = async (reader: WasmReader, width: number): Promise<string> => {
  const bytes = await reader.take(width);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const value = width === 4 ? view.getFloat32(0, true) : view.getFloat64(0, true);
  // Preserve the payload bits (notably NaNs and negative zero).
  return `${Object.is(value, -0) ? "-0" : value} [${Array.from(bytes,
    byte => byte.toString(16).padStart(2, "0")).join(" ")}]`;
};

export const readBlockType = async (reader: WasmReader): Promise<string> => {
  const value = await reader.signed(33);
  if (value === -64n) return "";
  if (value === -29n || value === -28n) {
    return `ref ${value === -29n ? "null " : ""}${await readHeapType(reader)}`;
  }
  if (value >= 0n) return `type ${value}`;
  const type = VALUE_TYPES[Number(value) + 128];
  if (!type) throw new Error(`Unsupported block type ${value}`);
  return type;
};

const readTryTable = async (reader: WasmReader): Promise<string> => {
  const type = await readBlockType(reader);
  const handlers = await reader.vector(async () => {
    const kind = await reader.byte();
    if (kind > 3) throw new Error("Invalid try_table catch kind");
    return `${kind}:${kind < 2 ? `${await reader.u32()}:` : ""}${await reader.u32()}`;
  });
  return `${type} ${handlers.join(" ")}`;
};

const readControlOperands = async (reader: WasmReader, opcode: number): Promise<string> => {
  if ([2, 3, 4, 6].includes(opcode)) return readBlockType(reader);
  if (opcode === 0x1f) return readTryTable(reader);
  if ([7, 8, 9, 0x0c, 0x0d, 0x10, 0x12, 0x14, 0x15, 0x18, 0x20, 0x21, 0x22,
    0x23, 0x24, 0x25, 0x26, 0x3f, 0x40, 0xd2, 0xd5, 0xd6].includes(opcode)) {
    return String(await reader.u32());
  }
  if (opcode === 0x0e) {
    return `${(await reader.vector(() => reader.u32())).join(" ")} default=${await reader.u32()}`;
  }
  if (opcode === 0x11 || opcode === 0x13) return `${await reader.u32()} table=${await reader.u32()}`;
  if (opcode === 0x1c) return (await reader.vector(() => readValueType(reader))).join(" ");
  return "";
};

export const readCoreOperands = async (reader: WasmReader, opcode: number): Promise<string> => {
  if (opcode < 0x28) return readControlOperands(reader, opcode);
  if (opcode <= 0x3e) return readMemoryArgument(reader);
  if ([0x3f, 0x40].includes(opcode)) return String(await reader.u32());
  if ([0x41, 0x42].includes(opcode)) return String(await reader.signed(opcode === 0x41 ? 32 : 64));
  if ([0x43, 0x44].includes(opcode)) return readFloat(reader, opcode === 0x43 ? 4 : 8);
  return readReferenceOperands(reader, opcode);
};

const readReferenceOperands = async (reader: WasmReader, opcode: number): Promise<string> => {
  if (opcode === 0xd0) return String(await readHeapType(reader));
  if ([0xd2, 0xd5, 0xd6].includes(opcode)) return String(await reader.u32());
  return "";
};

export const readBulkOperands = async (reader: WasmReader, opcode: number): Promise<string> => {
  if ([8, 10, 12, 14].includes(opcode)) return `${await reader.u32()} ${await reader.u32()}`;
  if ([9, 11, 13, 15, 16, 17].includes(opcode)) return String(await reader.u32());
  return "";
};

export const readSimdOperands = async (reader: WasmReader, opcode: number): Promise<string> => {
  if (opcode <= 11 || [92, 93].includes(opcode)) return readMemoryArgument(reader);
  if (opcode === 12 || opcode === 13) {
    return Array.from(await reader.take(16), byte => byte.toString(16).padStart(2, "0")).join(" ");
  }
  if (opcode >= 21 && opcode <= 34) return String(await reader.byte());
  if (opcode >= 84 && opcode <= 91) {
    return `${await readMemoryArgument(reader)} lane=${await reader.byte()}`;
  }
  return "";
};
