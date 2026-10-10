import type { GcBitReader } from "./gc-bit-reader.js";
import type { ManagedGcInfo } from "./gc-info-types.js";
import { readGcLiveState } from "./gc-live-state.js";

interface GcChunkSlot { slot: number; finalLive: boolean; offsets: number[] }

const chunkSlots = (reader: GcBitReader, tracked: number): GcChunkSlot[] => {
  const slots = readGcLiveState(reader, tracked);
  const states = slots.map(slot => ({ slot, finalLive: !!reader.bits(1), offsets: [] as number[] }));
  for (const state of states) {
    let previous = 0;
    while (reader.bits(1)) {
      const offset = reader.bits(6);
      if (offset <= previous) throw new Error("GC transitions must have increasing chunk offsets.");
      previous = offset;
      state.offsets.push(offset);
    }
  }
  return states;
};

const appendChunk = (states: GcChunkSlot[], base: number, length: number,
  liveAtEnd: Map<number, boolean>, transitions: ManagedGcInfo["transitions"]): void => {
  for (const state of states) {
    let live = state.finalLive !== (state.offsets.length % 2 === 1);
    if (live !== (liveAtEnd.get(state.slot) ?? false)) {
      transitions.push({ offset: base, slot: state.slot, live });
    }
    for (const delta of state.offsets) {
      if (base + delta >= length) throw new Error("GC transition is outside its interruptible range.");
      live = !live;
      transitions.push({ offset: base + delta, slot: state.slot, live });
    }
    liveAtEnd.set(state.slot, state.finalLive);
  }
};

const mapRanges = (transitions: ManagedGcInfo["transitions"],
  ranges: ManagedGcInfo["interruptibleRanges"]): void => {
  transitions.sort((left, right) => left.offset - right.offset);
  let index = 0;
  let precedingLength = 0;
  for (const transition of transitions) {
    while (transition.offset >= precedingLength + ranges[index]!.endOffset - ranges[index]!.startOffset) {
      precedingLength += ranges[index]!.endOffset - ranges[index]!.startOffset;
      index++;
    }
    transition.offset += ranges[index]!.startOffset - precedingLength;
  }
};

// GCInfoEncoder::Build stores chunks of 64 normalized code offsets. A chunk's final
// state plus the parity of its transitions determines the initial state; offset-zero
// transitions are intentionally omitted by the encoder. Ranges form a concatenated timeline.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/gcinfo/gcinfoencoder.cpp
export const readGcTransitions = (reader: GcBitReader,
  ranges: ManagedGcInfo["interruptibleRanges"], tracked: number): ManagedGcInfo["transitions"] => {
  const transitions: ManagedGcInfo["transitions"] = [];
  const length = ranges.reduce((sum, range) => sum + range.endOffset - range.startOffset, 0);
  if (!length || !tracked) return transitions;
  const width = reader.unsigned(3);
  if (!width) return transitions;
  const pointers: number[] = [];
  for (let index = 0; index < Math.ceil(length / 64); index++) pointers.push(reader.bits(width));
  const start = Math.ceil(reader.position / 8) * 8;
  const cache = new Map<number, GcChunkSlot[]>();
  const liveAtEnd = new Map<number, boolean>();
  for (const [index, pointer] of pointers.entries()) {
    if (!pointer) continue;
    const states = cache.get(pointer) ?? chunkSlots(reader.at(start + pointer - 1), tracked);
    cache.set(pointer, states);
    appendChunk(states, index * 64, length, liveAtEnd, transitions);
  }
  mapRanges(transitions, ranges);
  return transitions;
};
