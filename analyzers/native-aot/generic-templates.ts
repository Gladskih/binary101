import type { NativeFormatCursor } from "./native-format-cursor.js";
import type { NativeAotCodeReferences } from "./code-references.js";
import type { NativeAotTemplateMethodEntry } from "./function-map-types.js";
import { readTemplateMethodSignature } from "./template-signature.js";

// Layout offsets may be shared by different hash entries. Retain both successful and
// failed decoding per immutable section reader, without keeping completed parses alive.
const signatures = new WeakMap<NativeFormatCursor["reader"],
  Map<number, Promise<ReturnType<typeof readTemplateMethodSignature>>>>();

const signatureAt = (layout: NativeFormatCursor, offset: number, types: Map<number, number>) => {
  const cache = signatures.get(layout.reader) ??
    new Map<number, Promise<ReturnType<typeof readTemplateMethodSignature>>>();
  signatures.set(layout.reader, cache);
  const cached = cache.get(offset);
  if (cached) return cached;
  const result = Promise.resolve().then(() => readTemplateMethodSignature(layout.fork(offset), types));
  cache.set(offset, result);
  return result;
};

export const readTemplateMethodEntry = async (
  cursor: NativeFormatCursor, layout: NativeFormatCursor,
  references: NativeAotCodeReferences, types: Map<number, number>
): Promise<NativeAotTemplateMethodEntry> => {
  // Two NativeLayoutInfo offsets; only the method signature's optional function pointer is code.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/GenericMethodsTemplateMap.cs
  const signatureOffset = cursor.unsigned();
  const layoutOffset = cursor.unsigned();
  if (layoutOffset >= layout.reader.size) throw new Error("Template layout offset is outside NativeLayoutInfo.");
  const { entrypointIndex, ...signature } = await signatureAt(layout, signatureOffset, types);
  references.validateDataIndex(signature.declaringTypeIndex);
  signature.genericArgumentIndices.forEach(index => references.validateDataIndex(index));
  return { signatureOffset, layoutOffset, ...signature,
    entrypointRva: entrypointIndex === null ? null : await references.resolve(entrypointIndex) };
};
