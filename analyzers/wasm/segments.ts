import type { WasmReader } from "./reader.js";
import type { WasmCode, WasmData, WasmElement, WasmInstruction, WasmParseResult } from "./types.js";
import { readValueType } from "./value-types.js";
import { readExpression } from "./instructions.js";

// Segment flags and body encodings: https://webassembly.github.io/spec/core/binary/modules.html
const readData = async (reader: WasmReader): Promise<WasmData> => {
  const flags = await reader.u32();
  if (flags > 2) throw new Error(`Unsupported data segment flags ${flags}`);
  const memory = flags === 1 ? null : flags === 2 ? await reader.u32() : 0;
  const expression = flags === 1 ? [] : await readExpression(reader);
  const size = await reader.u32();
  const offset = reader.offset;
  reader.check(size);
  // A byte preview is display metadata; the complete segment range remains recorded.
  const preview = [...await reader.take(Math.min(size, 32))];
  await reader.skip(size - preview.length);
  return { mode: flags === 1 ? "passive" : "active", memory, expression, offset, size, preview };
};

const readElementType = async (reader: WasmReader, flags: number): Promise<string> => {
  if (flags & 4) return flags === 4 ? "funcref" : readValueType(reader);
  if (flags !== 0 && await reader.byte() !== 0) throw new Error("Invalid element kind");
  return "funcref";
};

const readElement = async (reader: WasmReader): Promise<WasmElement> => {
  const flags = await reader.u32();
  if (flags > 7) throw new Error(`Unsupported element segment flags ${flags}`);
  const active = (flags & 1) === 0;
  const table = active ? flags & 2 ? await reader.u32() : 0 : null;
  const expression = active ? await readExpression(reader) : [];
  const type = await readElementType(reader, flags);
  const entries: (number | WasmInstruction[])[] = flags & 4
    ? await reader.vector(() => readExpression(reader)) : await reader.vector(() => reader.u32());
  return { mode: active ? "active" : flags & 2 ? "declarative" : "passive",
    table, expression, type, entries };
};

const readCode = async (reader: WasmReader, result: WasmParseResult): Promise<WasmCode> => {
  const size = await reader.u32();
  const offset = reader.offset;
  const body = reader.child(size);
  const code: WasmCode = { offset, size, locals: [], instructions: [] };
  try {
    code.locals = await body.vector(async () => ({ count: await body.u32(),
      type: await readValueType(body) }));
    await readExpression(body, code.instructions);
    body.finish();
  } catch (error) {
    result.issues.push(`Function body at ${offset}: ${String(error)}`);
    await body.skip(body.remaining);
  }
  return code;
};

export const parseSegments = async (id: number, reader: WasmReader,
  result: WasmParseResult): Promise<void> => {
  if (id === 9) await reader.vector(() => readElement(reader), result.elements);
  if (id === 10) await reader.vector(() => readCode(reader, result), result.code);
  if (id === 11) await reader.vector(() => readData(reader), result.data);
};
