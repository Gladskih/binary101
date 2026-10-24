import { DEFAULT_FILE_READ_WINDOW_BYTES, type FileRangeReader } from "../../file-range-reader.js";

export interface Ia64DescriptorStatistics {
  counts: Record<string, number>;
  regionLengths: Record<"prologue" | "body", { count: number; minimumSlots?: string; maximumSlots?: string }>;
  savedRegisterRules: Record<string, number>;
  registerSaveLocations: Record<string, number>;
  spillScheduleSlots: Record<string, number>;
  abiContextCounts: Record<string, number>;
  maximumFixedStackBytes?: number;
  issues: string[];
}

// Intel 245358-003, chapter 11 and appendix B; libunwind's generic IA64 decoder.
// https://kib.kiev.ua/x86docs/Intel/Itanium/misc/245358-003.pdf
// Windows compatibility: https://groups.google.com/g/microsoft.public.windbg/c/iX3KQeqe3_E
// https://github.com/libunwind/libunwind/blob/v1.8.1/src/ia64/unwind_decoder.h
// Only aggregate metadata: this does not execute an unwind or rebuild machine state.
class DescriptorReader {
  position = 0;
  error: string | undefined;
  private window: Uint8Array = new Uint8Array(0);
  private windowStart = 0;
  private end: number;
  constructor(readonly source: FileRangeReader) { this.end = source.size; }
  async byte(): Promise<number> {
    if (this.position >= this.end) {
      this.error ??= "IA64 unwind descriptor is truncated.";
      return 0;
    }
    if (this.position >= this.windowStart + this.window.length) {
      this.windowStart = this.position;
      this.window = await this.source.readBytes(this.position,
        Math.min(DEFAULT_FILE_READ_WINDOW_BYTES, this.end - this.position));
      if (this.window.length < Math.min(DEFAULT_FILE_READ_WINDOW_BYTES, this.end - this.position)) {
        this.end = this.position + this.window.length;
      }
    }
    const value = this.window[this.position - this.windowStart];
    if (value == null) {
      this.error ??= "IA64 unwind descriptor read is truncated.";
      return 0;
    }
    this.position++;
    return value;
  }
  skip(length: bigint): void {
    if (length > BigInt(this.end - this.position)) {
      this.error ??= "IA64 unwind descriptor is truncated.";
    } else this.position += Number(length);
  }
  async unsigned(): Promise<bigint> {
    let value = 0n;
    for (let shift = 0n; shift < 64n; shift += 7n) {
      const part = await this.byte();
      value |= BigInt(part & 127) << shift;
      if (value > 0xffffffffffffffffn) break;
      if (!(part & 128)) return value;
    }
    this.error ??= "IA64 unwind descriptor ULEB128 exceeds 64 bits.";
    return 0n;
  }
}

interface DescriptorState {
  reader: DescriptorReader;
  body: boolean;
  hasRegion: boolean;
  regionSlots: bigint;
  statistics: Ia64DescriptorStatistics;
}

const reserved = (reader: DescriptorReader): string => {
  reader.error ??= "Unknown or reserved IA64 unwind descriptor encoding.";
  return "";
};

const bitCount = (value: number): number => {
  let remaining = value;
  let count = 0;
  while (remaining) {
    count += remaining & 1;
    remaining >>>= 1;
  }
  return count;
};

const addCount = (counts: Record<string, number>, name: string, count: number): void => {
  if (count) counts[name] = (counts[name] ?? 0) + count;
};

const recordRegionLength = (state: DescriptorState): void => {
  if (state.reader.error) return;
  const key = state.body ? "body" : "prologue";
  const region = state.statistics.regionLengths[key];
  const slots = state.regionSlots.toString();
  region.count++;
  if (region.minimumSlots == null || state.regionSlots < BigInt(region.minimumSlots)) region.minimumSlots = slots;
  if (region.maximumSlots == null || state.regionSlots > BigInt(region.maximumSlots)) region.maximumSlots = slots;
};

const parseRegion = async (state: DescriptorState, code: number): Promise<string> => {
  if (code < 0x40) {
    state.body = (code & 0x20) !== 0;
    state.regionSlots = BigInt(code & 31);
  } else if (code >= 0x40 && code <= 0x47) {
    const operand = await state.reader.byte(); // R2 saved-register mask and first GR.
    if (!state.reader.error) {
      const mask = (code & 0x07) | ((operand >>> 4) & 0x08);
      for (const [bit, name] of [[0, "psp"], [1, "pfs"], [2, "rp"], [3, "predicates"]] as const) {
        if (mask & (1 << bit)) addCount(state.statistics.savedRegisterRules,
          `${name} in general registers`, 1);
      }
    }
    state.body = false;
    state.regionSlots = await state.reader.unsigned();
  } else if (code === 0x60 || code === 0x61) {
    state.body = code === 0x61;
    state.regionSlots = await state.reader.unsigned();
  } else return reserved(state.reader);
  state.hasRegion = true;
  recordRegionLength(state);
  if (state.body) return "Body regions";
  return state.regionSlots ? "Prologue regions" : "Empty prologues / padding";
};

const parseStackRule = async (state: DescriptorState, code: number): Promise<string> => {
  await state.reader.unsigned(); // P7 time, stack offset, or spill-base displacement.
  if (code === 0xe0) {
    const bytes = await state.reader.unsigned() * 16n;
    if (state.reader.error) return "";
    if (bytes > BigInt(Number.MAX_SAFE_INTEGER)) {
      state.statistics.issues.push("IA64 fixed stack size exceeds the exact numeric range.");
    } else state.statistics.maximumFixedStackBytes =
      Math.max(state.statistics.maximumFixedStackBytes ?? 0, Number(bytes));
    return "Fixed stack allocations";
  }
  if (code === 0xe1) return "Variable stack allocations";
  return code === 0xe2 ? "Spill-base changes" : "Register rules";
};

const parseLongPrologueRule = async (state: DescriptorState, code: number): Promise<string> => {
  if (code === 0xf0) {
    const selector = await state.reader.byte();
    if (selector < 1 || selector > 19) return reserved(state.reader);
    await state.reader.unsigned();
    return "Register rules";
  }
  if (code === 0xf1) {
    state.reader.skip(2n);
    return "Register rules";
  }
  if (code === 0xff) {
    const abi = await state.reader.byte();
    const context = await state.reader.byte();
    if (state.reader.error) return "";
    // Intel 245358-003 Appendix B.3 defines ABI 2 as Windows NT; context is ABI-specific.
    const name = abi === 0 ? "Unix SVR4" : abi === 1 ? "HP-UX" : abi === 2 ? "Windows NT" : `ABI ${abi}`;
    addCount(state.statistics.abiContextCounts, `${name} context 0x${context.toString(16)}`, 1);
    return "ABI context records";
  }
  return reserved(state.reader);
};

const parseSpillRule = async (state: DescriptorState, code: number): Promise<string> => {
  if (code === 0xb8) {
    // P4 has one two-bit spill-schedule entry per instruction slot, MSB first.
    for (let slot = 0n; slot < state.regionSlots; slot += 4n) {
      const schedule = await state.reader.byte();
      if (state.reader.error) break;
      for (let entry = 0n; entry < 4n && slot + entry < state.regionSlots; entry++) {
        const kind = (schedule >>> (6 - Number(entry) * 2)) & 3;
        const name = ["empty spill slots", "floating-point registers from spill schedule",
          "general registers from spill schedule", "branch registers from spill schedule"][kind]!;
        state.statistics.spillScheduleSlots[name] = (state.statistics.spillScheduleSlots[name] ?? 0) + 1;
      }
    }
    return "Spill schedules";
  }
  if (code === 0xb9) {
    const [first, second, third] = [await state.reader.byte(), await state.reader.byte(), await state.reader.byte()];
    if (state.reader.error) return "";
    addCount(state.statistics.savedRegisterRules, "general registers in memory", bitCount(first >> 4));
    addCount(state.statistics.savedRegisterRules, "floating-point registers in memory",
      bitCount((first & 0x0f) * 0x10000 + second * 0x100 + third));
    return "Register rules";
  }
  return reserved(state.reader);
};

const parseSpecialRegisterRule = async (state: DescriptorState, code: number): Promise<string> => {
  const selector = (code & 7) * 2 + ((await state.reader.byte()) >>> 7);
  if (state.reader.error) return "";
  const register = ["psp", "rp", "pfs", "predicates", "unat", "lc", "rp", "rnat",
    "bsp", "bspstore", "fpsr", "priunat"][selector];
  if (register == null) return reserved(state.reader);
  addCount(state.statistics.savedRegisterRules,
    `${register} in ${selector === 6 ? "branch" : "general"} register`, 1);
  return "Register rules";
};

const parsePrologueRule = async (state: DescriptorState, code: number): Promise<string> => {
  if (code < 0xa0) {
    addCount(state.statistics.savedRegisterRules, "branch registers in memory", bitCount(code & 0x1f));
    return "Register rules"; // P1.
  }
  if (code < 0xb0) {
    const operand = await state.reader.byte(); // P2 branch-register mask and first GR.
    if (!state.reader.error) addCount(state.statistics.savedRegisterRules,
      "branch registers in general registers", bitCount(((code & 0x0f) << 1) | (operand >>> 7)));
    return "Register rules";
  }
  if (code < 0xb8) return parseSpecialRegisterRule(state, code);
  if (code < 0xc0) return parseSpillRule(state, code);
  if (code < 0xe0) {
    const count = bitCount(code & 0x0f);
    addCount(state.statistics.savedRegisterRules,
      code & 0x10 ? "general registers in memory" : "floating-point registers in memory", count);
    return "Register rules"; // P6 floating/general register mask.
  }
  if (code < 0xf0) return parseStackRule(state, code);
  return parseLongPrologueRule(state, code);
};

const parseBodyRule = async (state: DescriptorState, code: number): Promise<string> => {
  if (code < 0xc0) return code & 0x20 ? "Saved-state copies" : "Saved-state labels";
  if (code < 0xe0) {
    await state.reader.unsigned();
    return "Epilogues";
  }
  if (code === 0xe0) {
    await state.reader.unsigned();
    await state.reader.unsigned();
    return "Epilogues";
  }
  if (code === 0xf0 || code === 0xf8) {
    await state.reader.unsigned();
    return code === 0xf8 ? "Saved-state copies" : "Saved-state labels";
  }
  return reserved(state.reader);
};

const parseGeneralRule = async (state: DescriptorState, code: number): Promise<string> => {
  // Intel 245358-003 Appendix B.5: X1/X3 spill to memory; X2/X4 copy or restore registers.
  const first = await state.reader.byte();
  if (code === 0xf9 || code === 0xfb) {
    if (code === 0xfb) await state.reader.byte();
    await state.reader.unsigned();
    await state.reader.unsigned();
    if (!state.reader.error) addCount(state.statistics.registerSaveLocations,
      first & 0x80 ? "SP-relative memory spill rules" : "PSP-relative memory spill rules", 1);
    return "Register rules";
  }
  const second = await state.reader.byte();
  const third = code === 0xfc ? await state.reader.byte() : undefined;
  await state.reader.unsigned();
  if (state.reader.error) return "";
  const isRestore = code === 0xfc ? (second & 0x80) === 0 && third === 0
    : (first & 0x80) === 0 && second === 0;
  addCount(state.statistics.registerSaveLocations,
    isRestore ? "register restore rules" : "register-to-register spill rules", 1);
  return "Register rules";
};

const parseDescriptor = async (state: DescriptorState, code: number): Promise<string> => {
  if (code < 0x80) return parseRegion(state, code);
  if (!state.hasRegion) {
    state.reader.error = "IA64 unwind descriptor precedes its region header.";
    return "";
  }
  if (code >= 0xf9 && code <= 0xfc) return parseGeneralRule(state, code);
  return state.body ? parseBodyRule(state, code) : parsePrologueRule(state, code);
};

export const parseIa64Descriptors = async (source: FileRangeReader): Promise<Ia64DescriptorStatistics> => {
  const statistics: Ia64DescriptorStatistics = { counts: {},
    regionLengths: { prologue: { count: 0 }, body: { count: 0 } }, savedRegisterRules: {},
    registerSaveLocations: {}, spillScheduleSlots: {}, abiContextCounts: {}, issues: [] };
  if (!Number.isSafeInteger(source.size) || source.size < 0) {
    statistics.issues.push("IA64 unwind descriptor area size is invalid.");
    return statistics;
  }
  const state: DescriptorState = { reader: new DescriptorReader(source), body: false,
    hasRegion: false, regionSlots: 0n, statistics };
  while (state.reader.position < source.size && !state.reader.error) {
    const kind = await parseDescriptor(state, await state.reader.byte());
    if (!state.reader.error) statistics.counts[kind] = (statistics.counts[kind] ?? 0) + 1;
  }
  if (state.reader.error) statistics.issues.push(state.reader.error);
  return statistics;
};
