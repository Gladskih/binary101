import type { NativeFormatCursor } from "./native-format-cursor.js";
import { readTemplateTypeReference } from "./template-type-references.js";
import { readLayoutMethodIdentity, type NativeAotMethodIdentity } from "./layout-method-identity.js";

export const readTemplateMethodSignature = (
  cursor: NativeFormatCursor, types: Map<number, number>
): NativeAotMethodIdentity & { flags: number; declaringTypeIndex: number;
  genericArgumentIndices: number[]; entrypointIndex: number | null } => {
  // MethodFlags and field ordering come from NativeLayoutInfoLoadContext.GetMethod.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/System.Private.TypeLoader/src/Internal/Runtime/TypeLoader/NativeLayoutInfoLoadContext.cs
  const flags = cursor.unsigned();
  if (flags & ~(cursor.reader.layout === "dotnet9" ? 15 : 7)) {
    throw new Error("Template method signature has unknown flags.");
  }
  const entrypointIndex = flags & 4 ? cursor.unsigned() : null;
  const declaringTypeIndex = readTemplateTypeReference(cursor, types);
  const identity = readLayoutMethodIdentity(cursor);
  const genericArgumentIndices: number[] = [];
  if (flags & 1) {
    const count = cursor.count();
    for (let index = 0; index < count; index += 1) {
      genericArgumentIndices.push(readTemplateTypeReference(cursor, types));
    }
  }
  return { flags, declaringTypeIndex, ...identity, genericArgumentIndices, entrypointIndex };
};
