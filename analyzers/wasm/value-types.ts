import type { WasmReader } from "./reader.js";
import type { WasmGlobalType, WasmLimits, WasmTable } from "./types.js";

// https://webassembly.github.io/spec/core/binary/types.html
export const VALUE_TYPES: Readonly<Record<number, string>> = {
  0x7f: "i32", 0x7e: "i64", 0x7d: "f32", 0x7c: "f64", 0x7b: "v128",
    0x70: "funcref", 0x6f: "externref", 0x6e: "anyref", 0x6d: "eqref", 0x6c: "i31ref",
    0x6b: "structref", 0x6a: "arrayref", 0x69: "exnref", 0x71: "nullref",
  0x72: "nullexternref", 0x73: "nullfuncref", 0x74: "nullexnref"
};

export const readHeapType = async (reader: WasmReader): Promise<bigint> => {
  const type = await reader.signed(33);
  if (type < 0n && (type < -23n || type > -12n)) throw new Error(`Unsupported heap type ${type}`);
  return type;
};

export const readValueType = async (reader: WasmReader): Promise<string> => {
  const byte = await reader.byte();
  const type = VALUE_TYPES[byte];
  if (type) return type;
  if (byte === 0x63 || byte === 0x64) {
    return `ref ${byte === 0x63 ? "null " : ""}${await readHeapType(reader)}`;
  }
  throw new Error(`Unsupported value type 0x${byte.toString(16)}`);
};

export const readLimits = async (reader: WasmReader): Promise<WasmLimits> => {
  const flags = await reader.byte();
  if (flags > 7) throw new Error(`Unsupported limits flags 0x${flags.toString(16)}`);
  const min = await reader.unsigned(flags & 4 ? 64 : 32);
  const max = flags & 1 ? await reader.unsigned(flags & 4 ? 64 : 32) : null;
  if (max !== null && max < min) throw new Error("Limits maximum is below minimum");
  if ((flags & 2) && max === null) throw new Error("Shared limits require a maximum");
  return { min, max, shared: !!(flags & 2), address64: !!(flags & 4) };
};

export const readTable = async (reader: WasmReader): Promise<WasmTable> => {
  const type = await readValueType(reader);
  if (["i32", "i64", "f32", "f64", "v128"].includes(type)) {
    throw new Error("Table element must be a reference type");
  }
  const limits = await readLimits(reader);
  if (limits.shared) throw new Error("Shared tables are not supported");
  return { type, limits };
};

export const readGlobalType = async (reader: WasmReader): Promise<WasmGlobalType> => {
  const type = await readValueType(reader);
  const mutability = await reader.byte();
  if (mutability > 1) throw new Error("Invalid global mutability");
  return { type, mutable: mutability === 1 };
};

export const readTag = async (reader: WasmReader): Promise<number> => {
  if (await reader.byte() !== 0) throw new Error("Unsupported tag attribute");
  return reader.u32();
};
