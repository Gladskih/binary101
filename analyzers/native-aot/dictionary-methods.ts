import type { NativeFormatCursor } from "./native-format-cursor.js";
import type { NativeLayoutTypeReader } from "./layout-type.js";
import { readLayoutMethod } from "./layout-methods.js";

// Dictionary cells are inline signatures, not pointers to cells. Resulting dictionaries can
// contain data; only HasFunctionPointer fields inside method signatures describe code.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/System.Private.TypeLoader/src/Internal/Runtime/TypeLoader/GenericDictionaryCell.cs
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/NativeLayoutVertexNode.cs
const readCell = (cursor: NativeFormatCursor, types: NativeLayoutTypeReader,
  issues: Set<string>): ReturnType<typeof readLayoutMethod> | null => {
  const kind = cursor.unsigned();
  if ([4, 8, 13].includes(kind)) return readLayoutMethod(cursor, types);
  if (kind === 34) { types.skip(cursor); return readLayoutMethod(cursor, types); }
  if (kind === 238) {
    cursor.unsigned();
    issues.add("NativeLayout dictionary contains a NotYetSupported cell.");
    return null;
  }
  if (![1, 2, 5, 6, 7, 9, 10, 11, 32, 33].includes(kind)) {
    throw new Error("NativeLayout dictionary cell has an unknown kind.");
  }
  types.skip(cursor);
  if (kind === 32 || kind === 33) types.skip(cursor);
  if ([2, 5, 7, 32, 33].includes(kind)) cursor.unsigned();
  return null;
};

export const readDictionaryMethods = (cursor: NativeFormatCursor, types: NativeLayoutTypeReader,
  issues: Set<string>): ReturnType<typeof readLayoutMethod>[] => {
  const methods: ReturnType<typeof readLayoutMethod>[] = [];
  try {
    const count = cursor.count();
    for (let index = 0; index < count; index += 1) {
      const method = readCell(cursor, types, issues);
      if (method) methods.push(method);
    }
  } catch (error) {
    issues.add(error instanceof Error ? error.message : "NativeLayout dictionary read failed.");
  }
  return methods;
};
