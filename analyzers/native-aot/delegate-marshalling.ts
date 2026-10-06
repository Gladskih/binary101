import type { NativeFormatCursor } from "./native-format-cursor.js";
import type { NativeAotCodeReferences } from "./code-references.js";
import type { NativeAotDelegateMarshallingEntry } from "./function-map-types.js";

// Declaring type is data; the three following indices are MethodEntrypoint symbols.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/DelegateMarshallingStubMapNode.cs
export const readDelegateMarshallingEntry = async (
  cursor: NativeFormatCursor, references: NativeAotCodeReferences
): Promise<NativeAotDelegateMarshallingEntry> => {
  const typeIndex = cursor.unsigned();
  references.validateDataIndex(typeIndex);
  const openStatic = cursor.unsigned(), closed = cursor.unsigned(), forward = cursor.unsigned();
  return { typeIndex, openStaticRva: await references.resolve(openStatic),
    closedRva: await references.resolve(closed), forwardCreationRva: await references.resolve(forward) };
};
