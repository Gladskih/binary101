import type { NativeFormatCursor } from "./native-format-cursor.js";

const genericArguments = (cursor: NativeFormatCursor, flags: number):
  { genericArgumentIndices: number[]; genericMethodSignatureOffset?: number } => {
  if (!(flags & 2)) return { genericArgumentIndices: [] };
  if (cursor.reader.layout === "dotnet10") return { genericArgumentIndices: cursor.indices() };
  const signature = flags & 0x10 ? { genericMethodSignatureOffset: cursor.unsigned() } : {};
  return { ...signature, genericArgumentIndices: flags & 0x40 ? [] : cursor.indices() };
};

export const readNativeAotInvokeTuple = (cursor: NativeFormatCursor) => {
  // ReflectionInvokeMapNode.GetData and MappingTableFlags specify the ABI-specific tuple.
  // https://github.com/dotnet/runtime/blob/v9.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/ReflectionInvokeMapNode.cs
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/MappingTableFlags.cs
  const flags = cursor.unsigned();
  if (flags & ~(cursor.reader.layout === "dotnet9" ? 0x70ff : 0x70bb)) {
    throw new Error("Invoke map entry has unknown flags.");
  }
  const offset = cursor.unsigned();
  const identity = cursor.reader.layout === "dotnet9" && !(flags & 4) ?
    { nameAndSignatureOffset: offset } : { metadataOffset: offset };
  const declaringTypeIndex = cursor.unsigned();
  const entrypointIndex = flags & 0x20 ? cursor.unsigned() : null;
  const invokeStubIndex = flags & 0x80 ? null : cursor.unsigned();
  return { flags, ...identity, declaringTypeIndex, entrypointIndex, invokeStubIndex,
    ...genericArguments(cursor, flags) };
};
