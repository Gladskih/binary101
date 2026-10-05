import type { ReadyToRunSignatureCursor } from "./ready-to-run-signature-cursor.js";

type TypeTask = "type" | "array" | "arguments" | { types: number } | { parameters: number };
type TypeReader = (cursor: ReadyToRunSignatureCursor, tasks: TypeTask[]) => void;

// CorElementType and R2RSignatureDecoder.ParseType define this grammar.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/ReadyToRunSignature.cs#L639-L810
const primitives = new Set([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 22, 24, 25, 28, 62]);

const prefixType: TypeReader = (_cursor, tasks) => { tasks.push("type"); };
const indexedType: TypeReader = cursor => { cursor.unsigned(); };
const indexedPrefixType: TypeReader = (cursor, tasks) => { cursor.unsigned(); tasks.push("type"); };
const arrayType: TypeReader = (_cursor, tasks) => { tasks.push("array", "type"); };
const genericType: TypeReader = (_cursor, tasks) => { tasks.push("arguments", "type"); };
const functionType: TypeReader = (cursor, tasks) => {
  if (cursor.byte() & 0x10) cursor.unsigned(); // ECMA SignatureHeader.IsGeneric.
  tasks.push({ parameters: cursor.count() }, "type");
};

const typeReaders: Readonly<Record<number, TypeReader>> = {
  15: prefixType, 16: prefixType, 17: indexedType, 18: indexedType, 19: indexedType,
  20: arrayType, 21: genericType, 27: functionType, 29: prefixType, 30: indexedType,
  31: indexedPrefixType, 32: indexedPrefixType, 63: indexedPrefixType, 69: prefixType
};

const readType = (cursor: ReadyToRunSignatureCursor, tasks: TypeTask[]): void => {
  const element = cursor.byte() & 0x7f;
  if (primitives.has(element)) return;
  if (!typeReaders[element]) throw new Error(`Unsupported R2R type element ${element}.`);
  typeReaders[element]!(cursor, tasks);
};

const arrayShape = (cursor: ReadyToRunSignatureCursor): void => {
  const rank = cursor.unsigned();
  if (!rank) return;
  const sizes = cursor.count();
  if (sizes > rank) throw new Error("R2R array size count exceeds its rank.");
  for (let index = 0; index < sizes; index += 1) cursor.unsigned();
  const bounds = cursor.count();
  if (bounds > rank) throw new Error("R2R array lower-bound count exceeds its rank.");
  for (let index = 0; index < bounds; index += 1) cursor.unsigned();
};

const runTask = (
  cursor: ReadyToRunSignatureCursor, tasks: TypeTask[], task: TypeTask
): void => {
  if (task === "type") return readType(cursor, tasks);
  if (task === "array") return arrayShape(cursor);
  if (task === "arguments") { tasks.push({ types: cursor.count() }); return; }
  if ("types" in task) {
    if (task.types) tasks.push({ types: task.types - 1 }, "type");
    return;
  }
  if (!task.parameters) return;
  while (((cursor.peek() ?? 0) & 0x7f) === 0x41) cursor.byte(); // ReadElementType masks the high bit.
  tasks.push({ parameters: task.parameters - 1 }, "type");
};

export const skipReadyToRunType = (cursor: ReadyToRunSignatureCursor): void => {
  // Explicit grammar stack: nesting is constrained by available bytes, not a depth cap.
  const tasks: TypeTask[] = ["type"];
  while (tasks.length) runTask(cursor, tasks, tasks.pop()!);
};
