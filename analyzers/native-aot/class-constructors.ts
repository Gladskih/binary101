import type { NativeFormatCursor } from "./native-format-cursor.js";
import type { NativeAotFunctionReferences } from "./function-references.js";
// NonGCStaticsNode prefixes the base by one StaticClassConstructionContext pointer.
// The CommonFixups base is data; the preceding field is the exact callable cctor address.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/ClassConstructorContextMap.cs
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/NonGCStaticsNode.cs
export const readClassConstructor = async (cursor: NativeFormatCursor, references: NativeAotFunctionReferences):
  Promise<{ typeIndex: number; staticBaseIndex: number;
    entrypointRva: number | null }> => {
  const typeIndex = cursor.unsigned();
  const staticBaseIndex = cursor.unsigned();
  references.common.validateDataIndex(typeIndex);
  const base = await references.common.resolveData(staticBaseIndex);
  const pointer = base === null ? null : await references.data.pointer(base - references.image.pointerSize);
  return { typeIndex, staticBaseIndex, entrypointRva: pointer === null ? null :
    await references.pointers.resolve(pointer) };
};
