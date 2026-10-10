import type { ManagedGcInfo } from "../../analyzers/native-aot/gc-info-types.js";

/** FNV-1a/32 over query offsets and sorted tracked-slot IDs, separated by UInt32.MaxValue.
 * Every byte position of every interruptible range is checked, including intervals
 * without transitions; the runtime oracle chooses its queries from its own decoded ranges.
 */
export const managedGcLiveHash = (info: ManagedGcInfo, version: number): string => {
  let hash = 2166136261;
  const word = (value: number) => {
    for (let index = 0; index < 4; index++) {
      hash = Math.imul(hash ^ ((value >>> (index * 8)) & 255), 16777619) >>> 0;
    }
  };
  const query = (offset: number, slots: number[]) => {
    word(offset);
    slots.forEach(word);
    word(0xffffffff);
  };
  info.safePoints.forEach(point => query(point.offset + (version === 3 ? 1 : 0), point.liveSlots));
  const live = new Set<number>();
  let index = 0;
  for (const range of info.interruptibleRanges) {
    for (let offset = range.startOffset; offset < range.endOffset; offset++) {
      while (index < info.transitions.length && info.transitions[index]!.offset <= offset) {
        const event = info.transitions[index++]!;
        if (event.live) live.add(event.slot);
        else live.delete(event.slot);
      }
      query(offset, [...live].sort((left, right) => left - right));
    }
  }
  return hash.toString(16);
};
