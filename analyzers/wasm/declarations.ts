import type { WasmReader } from "./reader.js";
import type { WasmExternal, WasmParseResult, WasmType } from "./types.js";
import { readGlobalType, readLimits, readTable, readTag, readValueType } from "./value-types.js";
import { readExpression } from "./instructions.js";

// Section IDs and descriptors: https://webassembly.github.io/spec/core/binary/modules.html
export const EXTERNAL_KINDS: Readonly<Record<number, string>> = {
  0: "function", 1: "table", 2: "memory", 3: "global", 4: "tag"
};

const readFunctionType = async (reader: WasmReader): Promise<WasmType> => {
  if (await reader.byte() !== 0x60) throw new Error("Unsupported recursive/GC type definition");
  return { params: await reader.vector(() => readValueType(reader)),
    results: await reader.vector(() => readValueType(reader)) };
};

const readExternal = async (reader: WasmReader): Promise<WasmExternal> => {
  const kind = await reader.byte();
  switch (kind) {
    case 0: return { kind: "function", typeIndex: await reader.u32() };
    case 1: return { kind: "table", table: await readTable(reader) };
    case 2: return { kind: "memory", limits: await readLimits(reader) };
    case 3: return { kind: "global", global: await readGlobalType(reader) };
    case 4: return { kind: "tag", typeIndex: await readTag(reader) };
    default: throw new Error(`Unsupported import kind ${kind}`);
  }
};

const DECLARATION_READERS: Record<number,
  (reader: WasmReader, result: WasmParseResult) => Promise<unknown>> = {
  1: (reader, result) => reader.vector(() => readFunctionType(reader), result.types),
  2: (reader, result) => reader.vector(async () => ({ module: await reader.name(),
    name: await reader.name(), descriptor: await readExternal(reader) }), result.imports),
  3: (reader, result) => reader.vector(async () => ({ typeIndex: await reader.u32() }), result.functions),
  4: (reader, result) => reader.vector(() => readTable(reader), result.tables),
  5: (reader, result) => reader.vector(() => readLimits(reader), result.memories),
  6: (reader, result) => reader.vector(async () => ({ descriptor: await readGlobalType(reader),
    expression: await readExpression(reader) }), result.globals),
  7: (reader, result) => reader.vector(async () => {
    const name = await reader.name();
    const kind = EXTERNAL_KINDS[await reader.byte()];
    if (!kind) throw new Error("Unsupported export kind");
    return { name, kind, index: await reader.u32() };
  }, result.exports),
  8: async (reader, result) => { result.start = await reader.u32(); },
  12: async (reader, result) => { result.dataCount = await reader.u32(); },
  13: (reader, result) => reader.vector(() => readTag(reader), result.tags)
};

export const parseDeclarations = async (id: number, reader: WasmReader,
  result: WasmParseResult): Promise<void> => {
  await DECLARATION_READERS[id]!(reader, result);
};
