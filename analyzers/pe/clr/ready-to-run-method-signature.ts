import { ReadyToRunSignatureCursor } from "./ready-to-run-signature-cursor.js";
import { skipReadyToRunType } from "./ready-to-run-type-grammar.js";

// ReadyToRunMethodSigFlags: UpdateContext=0x80, OwnerType=0x40, Instantiation=0x04,
// Constrained=0x20. The RID/slot field occupies one compressed uint in either case.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/ReadyToRunConstants.cs
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun/ReadyToRunSignature.cs#L824-L896
export const skipReadyToRunMethodSignature = (bytes: Uint8Array, offset: number): number => {
  const cursor = new ReadyToRunSignatureCursor(bytes, offset);
  const flags = cursor.unsigned();
  if (flags > 0xff) throw new Error("R2R method signature has unknown flags.");
  if (flags & 0x80) cursor.unsigned();
  if (flags & 0x40) skipReadyToRunType(cursor);
  cursor.unsigned();
  if (flags & 0x04) {
    const count = cursor.count();
    for (let index = 0; index < count; index += 1) skipReadyToRunType(cursor);
  }
  if (flags & 0x20) skipReadyToRunType(cursor);
  return cursor.offset;
};
