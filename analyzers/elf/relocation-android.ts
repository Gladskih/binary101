import type { ElfRelocationStream } from "./relocation-stream.js";
import type { ElfRelocation, ElfRelocationImage } from "./relocation-types.js";
import { decodeElfRelocationInfo } from "./relocation-info.js";

// APS2 groups: bit 0 groups info, bit 1 offset deltas, bit 2 addend delta,
// bit 3 supplies explicit addends. Grouped addends are applied once per group.
// https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/lib/Object/ELF.cpp
interface AndroidGroup {
  count: bigint;
  offsetDelta: bigint | null;
  info: bigint | null;
  addendDelta: bigint | null;
  hasAddend: boolean;
}

interface AndroidRelocationState { offset: bigint; addend: bigint }

const validFlags = (flags: bigint, encoding: string): boolean => {
  if (flags < 0n || flags > 15n) return false;
  if (flags & 4n && !(flags & 8n)) return false;
  return encoding !== "ANDROID_REL" || !(flags & 8n);
};

const readGroup = async (stream: ElfRelocationStream, remaining: bigint,
  encoding: string): Promise<AndroidGroup> => {
  const count = await stream.signed();
  const flags = await stream.signed();
  if (count <= 0n || count > remaining) throw new Error("invalid APS2 group count");
  if (!validFlags(flags, encoding)) throw new Error("invalid APS2 group flags");
  return { count, offsetDelta: flags & 2n ? await stream.signed() : null,
    info: flags & 1n ? await stream.signed() : null,
    addendDelta: flags & 4n ? await stream.signed() : null, hasAddend: (flags & 8n) !== 0n };
};

const readGroupRecord = async (stream: ElfRelocationStream, group: AndroidGroup,
  state: AndroidRelocationState, elf: ElfRelocationImage, encoding: string,
  tableIndex: number, recordOffset: number): Promise<ElfRelocation> => {
  const bits = elf.is64 ? 64 : 32;
  state.offset += group.offsetDelta ?? await stream.signed();
  const info = BigInt.asUintN(bits, group.info ?? await stream.signed());
  if (group.hasAddend && group.addendDelta == null) state.addend += await stream.signed();
  if (state.offset < 0n || state.offset >= 1n << BigInt(bits)) throw new Error("APS2 offset overflows address space");
  return { tableIndex, recordOffset, offset: state.offset, ...decodeElfRelocationInfo(info, elf),
    addend: encoding === "ANDROID_REL" ? null : BigInt.asIntN(bits, state.addend), symbol: null, target: null };
};

export async function* readElfAndroidRelocations(
  stream: ElfRelocationStream, elf: ElfRelocationImage, encoding: string, tableIndex: number
): AsyncGenerator<ElfRelocation> {
  for (const expected of [65, 80, 83, 50]) { // ASCII APS2 magic, independent of EI_DATA.
    if (await stream.byte() !== expected) throw new Error("invalid APS2 magic");
  }
  let remaining = await stream.signed();
  if (remaining < 0n) throw new Error("negative APS2 relocation count");
  const state: AndroidRelocationState = { offset: await stream.signed(), addend: 0n };
  while (remaining > 0n) {
    const groupOffset = stream.position;
    const group = await readGroup(stream, remaining, encoding);
    state.addend = group.hasAddend ? state.addend + (group.addendDelta ?? 0n) : 0n;
    for (let index = 0n; index < group.count; index++) {
      yield await readGroupRecord(stream, group, state, elf, encoding, tableIndex, groupOffset);
    }
    remaining -= group.count;
  }
}
