import type { NativeFormatCursor } from "./native-format-cursor.js";
import { nativeTypeLookbackOffset } from "./type-lookback.js";

// CreateInstantiatedSignature emits External types; NativeWriter can share them with Lookback.
// GetLookbackParser subtracts data + GetUnsignedEncodingSize(data << 4) + 2 from the next offset.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/NativeFormat/NativeFormatReader.Metadata.cs
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/NativeLayoutVertexNode.cs
export const readTemplateTypeReference = (
  cursor: NativeFormatCursor, cache: Map<number, number>
): number => {
  const visited: number[] = [];
  let current = cursor;
  let typeIndex: number;
  for (;;) {
    const start = current.offset;
    const value = current.unsigned();
    visited.push(start);
    const cached = cache.get(start);
    if (cached !== undefined) { typeIndex = cached; break; }
    if ((value & 15) === 6) { typeIndex = value >>> 4; break; }
    if ((value & 15) !== 1) throw new Error("Template signature has a non-external type reference.");
    const data = value >>> 4;
    const target = nativeTypeLookbackOffset(current.offset, data);
    if (target < 0 || target >= start) throw new Error("Template type lookback is out of bounds or cyclic.");
    current = cursor.fork(target);
  }
  visited.forEach(offset => cache.set(offset, typeIndex));
  return typeIndex;
};
