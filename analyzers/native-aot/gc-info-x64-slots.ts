import type { GcBitReader } from "./gc-bit-reader.js";
import type { ManagedGcSlot } from "./gc-info-types.js";

// GcSlotDecoder::DecodeSlotTable: stack deltas are unsigned, absolute offsets signed.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/vm/gcinfodecoder.cpp
const registers = (reader: GcBitReader, count: number, slots: ManagedGcSlot[]): void => {
  let register = 0;
  let flags = 0;
  for (let index = 0; index < count; index++) {
    if (index === 0 || flags) { register = reader.unsigned(3); flags = reader.bits(2); }
    else register += reader.unsigned(2) + 1;
    // GetRegisterSlot forbids RSP (4); NativeAOT's register pointer array omits it.
    // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/vm/gcinfodecoder.cpp
    if (register >= 16 || register === 4) throw new Error("GC register is invalid for AMD64 root storage.");
    slots.push({ kind: "register", register, flags });
  }
};

const stack = (reader: GcBitReader, count: number, groupFlags: number, slots: ManagedGcSlot[]): void => {
  let normalizedOffset = 0;
  let flags = 0;
  for (let index = 0; index < count; index++) {
    const base = reader.bits(2);
    if (base === 3) throw new Error("Unknown GC stack-slot base.");
    if (index === 0 || flags) { normalizedOffset = reader.signed(6); flags = reader.bits(2); }
    else normalizedOffset += reader.unsigned(4);
    const offset = normalizedOffset * 8;
    if (offset < -2147483648 || offset > 2147483647) throw new Error("GC stack offset exceeds Int32.");
    slots.push({ kind: "stack", base, offset, flags: flags | groupFlags });
  }
};

export const readX64GcSlots = (reader: GcBitReader, slots: ManagedGcSlot[] = []): ManagedGcSlot[] => {
  const registerCount = reader.bits(1) ? reader.unsigned(2) : 0;
  const hasStackSlots = reader.bits(1);
  const stackCount = hasStackSlots ? reader.unsigned(2) : 0;
  const untrackedCount = hasStackSlots ? reader.unsigned(1) : 0;
  registers(reader, registerCount, slots);
  stack(reader, stackCount, 0, slots);
  stack(reader, untrackedCount, 4, slots);
  return slots;
};
