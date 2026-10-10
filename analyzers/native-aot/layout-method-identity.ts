import type { NativeFormatCursor } from "./native-format-cursor.js";

export type NativeAotMethodIdentity = { methodToken: number } |
  { methodName: string; methodSignatureOffset: number };

export const relativeLayoutCursor = (cursor: NativeFormatCursor): NativeFormatCursor => {
  const field = cursor.reader.signed(cursor.offset);
  const target = cursor.offset + field.value;
  cursor.offset = field.nextOffset;
  if (target < 0 || target >= cursor.reader.size) throw new Error("NativeLayout relative signature is outside its section.");
  return cursor.fork(target);
};

export const readLayoutMethodIdentity = (cursor: NativeFormatCursor): NativeAotMethodIdentity => {
  // .NET 9 stores a UTF-8 name + relative method signature; .NET 10 stores a metadata handle.
  // https://github.com/dotnet/runtime/blob/v9.0.0/src/coreclr/nativeaot/System.Private.TypeLoader/src/Internal/Runtime/TypeLoader/TypeLoaderEnvironment.SignatureParsing.cs
  if (cursor.reader.layout === "dotnet10") return { methodToken: cursor.unsigned() };
  const methodName = cursor.string();
  return { methodName, methodSignatureOffset: relativeLayoutCursor(cursor).offset };
};
