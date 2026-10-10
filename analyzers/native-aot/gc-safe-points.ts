import type { GcBitReader } from "./gc-bit-reader.js";
import { readGcLiveBits, readGcLiveState } from "./gc-live-state.js";
import type { ManagedGcInfo } from "./gc-info-types.js";

// TGcInfoDecoder::EnumerateLiveSlots: indirect states begin on the next byte after
// the pointer table; pointers are bit offsets, unlike NativeFormat byte lookbacks.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/vm/gcinfodecoder.cpp
export const readGcSafePointStates = (reader: GcBitReader, points: ManagedGcInfo["safePoints"],
  trackedSlots: number): ManagedGcInfo["safePoints"] => {
  if (!trackedSlots) return points;
  const width = reader.bits(1) ? reader.unsigned(3) + 1 : 0;
  const statesStart = Math.ceil((reader.position + points.length * width) / 8) * 8;
  const cache = new Map<number, number[]>();
  for (const point of points) {
    if (!width) { point.liveSlots = readGcLiveBits(reader, trackedSlots); continue; }
    const position = statesStart + reader.bits(width);
    const liveSlots = cache.get(position) ?? readGcLiveState(reader.at(position), trackedSlots);
    cache.set(position, liveSlots);
    point.liveSlots = liveSlots;
  }
  return points;
};
