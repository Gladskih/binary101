import type { NativeFormatCursor } from "./native-format-cursor.js";
import type { NativeLayoutTypeReader } from "./layout-type.js";
import { readLayoutMethod } from "./layout-methods.js";
import { relativeLayoutCursor } from "./layout-method-identity.js";

// Dictionary cells are inline signatures, not pointers to cells. Resulting dictionaries can
// contain data; only HasFunctionPointer fields inside method signatures describe code.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/System.Private.TypeLoader/src/Internal/Runtime/TypeLoader/GenericDictionaryCell.cs
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/NativeLayoutVertexNode.cs
const readCell = (cursor: NativeFormatCursor, types: NativeLayoutTypeReader,
  issues: Set<string>): ReturnType<typeof readLayoutMethod> | null => {
  const kind = cursor.unsigned();
  // .NET 9 ldtoken/constrained cells indirect their signatures; .NET 10 makes them inline.
  // https://github.com/dotnet/runtime/blob/v9.0.0/src/coreclr/nativeaot/System.Private.TypeLoader/src/Internal/Runtime/TypeLoader/GenericDictionaryCell.cs
  if (cursor.reader.layout === "dotnet9") return readLegacyCell(kind, cursor, types, issues);
  return readInlineCell(kind, cursor, types, issues);
};

const readLegacyCell = (kind: number, cursor: NativeFormatCursor, types: NativeLayoutTypeReader,
  issues: Set<string>): ReturnType<typeof readLayoutMethod> | null => {
  if (kind === 7) {
    const signature = relativeLayoutCursor(cursor);
    types.skip(signature);
    signature.string();
    return null;
  }
  if (kind === 8) return readLayoutMethod(relativeLayoutCursor(cursor), types);
  if (kind === 34) { types.skip(cursor); return readLayoutMethod(relativeLayoutCursor(cursor), types); }
  if (kind === 32) throw new Error("NativeLayout .NET 9 dictionary cell has an unknown kind.");
  return readInlineCell(kind, cursor, types, issues);
};

const readInlineCell = (kind: number, cursor: NativeFormatCursor, types: NativeLayoutTypeReader,
  issues: Set<string>): ReturnType<typeof readLayoutMethod> | null => {
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
