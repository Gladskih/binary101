import type { NativeFormatCursor } from "./native-format-cursor.js";
import type { NativeLayoutTypeReader } from "./layout-type.js";
import { readLayoutMethodIdentity, type NativeAotMethodIdentity } from "./layout-method-identity.js";
// GetMethod grammar; type variables and nested types are legal in dictionary signatures.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/System.Private.TypeLoader/src/Internal/Runtime/TypeLoader/NativeLayoutInfoLoadContext.cs
export const readLayoutMethod = (cursor: NativeFormatCursor, types: NativeLayoutTypeReader):
NativeAotMethodIdentity & { signatureOffset: number; flags: number; entrypointIndex: number | null } => {
  const signatureOffset = cursor.offset;
  const flags = cursor.unsigned();
  if (flags & ~(cursor.reader.layout === "dotnet9" ? 15 : 7)) {
    throw new Error("NativeLayout method signature has unknown flags.");
  }
  const entrypointIndex = flags & 4 ? cursor.unsigned() : null;
  types.skip(cursor);
  const identity = readLayoutMethodIdentity(cursor);
  if (flags & 1) {
    const count = cursor.count();
    for (let index = 0; index < count; index += 1) types.skip(cursor);
  }
  return { signatureOffset, flags, ...identity, entrypointIndex };
};
