import type { GcBitReader } from "./gc-bit-reader.js";
import type { ManagedGcHeader } from "./gc-info-types.js";

// AMD64GcInfoEncoding and TGcInfoDecoder::PredecodeFatHeader (GCInfo v3/v4).
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/gcinfotypes.h
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/vm/gcinfodecoder.cpp
const validityRange = (reader: GcBitReader, header: ManagedGcHeader): void => {
  if (!(header.flags & 0x34)) return;
  const startOffset = reader.unsigned(5) + 1;
  const endOffset = header.flags & 4 ? header.codeLength - reader.unsigned(3) : startOffset + 1;
  if (startOffset >= endOffset || endOffset > header.codeLength) throw new Error("Invalid GC validity range.");
  header.validRange = { startOffset, endOffset };
};

const stackOffset = (reader: GcBitReader): number => {
  const offset = reader.signed(6) * 8;
  if (offset < -2147483648 || offset > 2147483647) throw new Error("GC frame offset exceeds Int32.");
  return offset;
};

const frameSlots = (reader: GcBitReader, header: ManagedGcHeader, version: 3 | 4): void => {
  if (header.flags & 4) header.cookieStackOffset = stackOffset(reader);
  if (version === 3 && (header.flags & 8)) header.parentStackOffset = stackOffset(reader);
  if (header.flags & 0x30) header.genericContextStackOffset = stackOffset(reader);
};

const frameLayout = (reader: GcBitReader, header: ManagedGcHeader): void => {
  if (header.flags & 0x40) {
    const register = reader.unsigned(3);
    if (register >= 16) throw new Error("GC frame register is outside the AMD64 register set.");
    header.stackBaseRegister = register ^ 5;
  }
  if (header.flags & 0x100) header.editAndContinueBytes = reader.unsigned(4);
  if (header.flags & 0x200) header.reversePInvokeStackOffset = stackOffset(reader);
  header.outgoingStackBytes = reader.unsigned(3) * 8;
  if (header.outgoingStackBytes > 0xffffffff) throw new Error("GC outgoing stack size exceeds UInt32.");
};

const headerStart = (reader: GcBitReader, version: 3 | 4): {
  header: ManagedGcHeader; format: "slim" | "fat"
} => {
  const format = reader.bits(1) ? "fat" : "slim";
  const flags = format === "fat" ? reader.bits(10) : reader.bits(1) * 64;
  if (flags & (version === 4 ? 0x0a : 0x02)) throw new Error("GC header uses reserved flags.");
  const header: ManagedGcHeader = { flags, codeLength: 0 };
  if (version === 3) header.returnKind = reader.bits(format === "fat" ? 4 : 2);
  header.codeLength = reader.unsigned(8);
  // GCInfoEncoder::Build requires a nonempty native method body.
  if (!header.codeLength) throw new Error("GC method has zero code length.");
  return { header, format };
};

export const readX64GcHeader = (reader: GcBitReader, version: 3 | 4):
  ReturnType<typeof headerStart> => {
  const { header, format } = headerStart(reader, version);
  if (format === "fat") {
    validityRange(reader, header);
    frameSlots(reader, header, version);
    frameLayout(reader, header);
  } else if (header.flags & 64) header.stackBaseRegister = 5;
  return { header, format };
};
