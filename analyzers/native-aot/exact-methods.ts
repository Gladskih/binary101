import type { NativeFormatCursor } from "./native-format-cursor.js";
import type { NativeAotCodeReferences } from "./code-references.js";
import type { NativeAotExactMethodEntry } from "./function-map-types.js";
import { readLayoutMethodIdentity } from "./layout-method-identity.js";

// Signature tuple (type, metadata token, argument sequence), followed by the method pointer index.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/ExactMethodInstantiationsNode.cs
export const readExactMethodEntry = async (
  cursor: NativeFormatCursor, references: NativeAotCodeReferences, layout?: NativeFormatCursor
): Promise<NativeAotExactMethodEntry> => {
  const declaringTypeIndex = cursor.unsigned();
  const methodToken = cursor.unsigned();
  // .NET 9's second field is an offset into NativeLayoutInfo, not a metadata handle.
  // https://github.com/dotnet/runtime/blob/v9.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/ExactMethodInstantiationsNode.cs
  const identity = layout?.reader.layout === "dotnet9" ?
    readLayoutMethodIdentity(layout.fork(methodToken)) : { methodToken };
  const genericArgumentIndices = cursor.indices();
  references.validateDataIndex(declaringTypeIndex);
  genericArgumentIndices.forEach(index => references.validateDataIndex(index));
  return { declaringTypeIndex, ...identity, genericArgumentIndices,
    entrypointRva: await references.resolve(cursor.unsigned()) };
};
