import type { NativeFormatCursor } from "./native-format-cursor.js";
import type { NativeAotCodeReferences } from "./code-references.js";
import type { NativeAotExactMethodEntry } from "./function-map-types.js";

// Signature tuple (type, metadata token, argument sequence), followed by the method pointer index.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/ExactMethodInstantiationsNode.cs
export const readExactMethodEntry = async (
  cursor: NativeFormatCursor, references: NativeAotCodeReferences
): Promise<NativeAotExactMethodEntry> => {
  const declaringTypeIndex = cursor.unsigned();
  const methodToken = cursor.unsigned();
  const genericArgumentIndices = cursor.indices();
  references.validateDataIndex(declaringTypeIndex);
  genericArgumentIndices.forEach(index => references.validateDataIndex(index));
  return { declaringTypeIndex, methodToken, genericArgumentIndices,
    entrypointRva: await references.resolve(cursor.unsigned()) };
};
