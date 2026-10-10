import type { GcBitReader } from "./gc-bit-reader.js";

export const readGcLiveBits = (reader: GcBitReader, count: number): number[] => {
  const slots: number[] = [];
  for (let slot = 0; slot < count; slot++) if (reader.bits(1)) slots.push(slot);
  return slots;
};

// GCInfoEncoder::WriteSlotStateVarLengthVector: the extra bit swaps encoding bases,
// not liveness. The first count always skips dead slots; subsequent counts are biased by 1.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/gcinfo/gcinfoencoder.cpp
const readRuns = (reader: GcBitReader, count: number, skipBase: number, runBase: number): number[] => {
  let position = reader.unsigned(skipBase);
  if (position > count) throw new Error("GC live-state skip exceeds slot count.");
  const slots: number[] = [];
  for (let run = 0; position < count; run++) {
    const length = reader.unsigned(run % 2 ? skipBase : runBase) + 1;
    if (position + length > count) throw new Error("GC live-state run exceeds slot count.");
    if (run % 2 === 0) {
      for (let slot = position; slot < position + length; slot++) slots.push(slot);
    }
    position += length;
  }
  return slots;
};

export const readGcLiveState = (reader: GcBitReader, count: number): number[] => {
  if (!reader.bits(1)) return readGcLiveBits(reader, count);
  const swap = reader.bits(1);
  return readRuns(reader, count, swap ? 2 : 4, swap ? 4 : 2);
};
