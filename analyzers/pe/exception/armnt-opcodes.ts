// ARM32 unwind bytecodes follow the opcode table in Microsoft's ARM exception
// handling specification, "Unwind Codes":
// https://learn.microsoft.com/en-us/cpp/build/arm-exception-handling
export interface ArmntOpcodeSummary {
  opcodeCounts: Record<string, number>;
  instructionCount: number;
  complete: boolean;
  stackAdjustments: number[];
  integerRegisterPopCount: number;
  floatingRegisterPopCount: number;
  framePointerRestores: number;
  returnAddressLoads: number;
  specialMarkers: Record<string, number>;
  unknownOpcodeCount: number;
}

const createSummary = (): ArmntOpcodeSummary => ({ opcodeCounts: {}, instructionCount: 0, complete: true,
  stackAdjustments: [], integerRegisterPopCount: 0, floatingRegisterPopCount: 0,
  framePointerRestores: 0, returnAddressLoads: 0, specialMarkers: {}, unknownOpcodeCount: 0 });

const marker = (summary: ArmntOpcodeSummary, name: string): void => {
  summary.specialMarkers[name] = (summary.specialMarkers[name] ?? 0) + 1;
};

const popCount = (mask: number): number => {
  let count = 0;
  for (let bits = mask; bits !== 0; bits &= bits - 1) count += 1;
  return count;
};

const decodeOne = (codes: Uint8Array, offset: number, summary: ArmntOpcodeSummary): number => {
  const first = codes[offset]!;
  const second = codes[offset + 1];
  summary.instructionCount += 1;
  const name = first <= 0x7f ? "stack add 16-bit" : first <= 0xbf ? "register pop 32-bit" :
    first <= 0xcf ? "restore SP from register" : first <= 0xdf ? "register pop 16/32-bit" :
      first <= 0xe7 ? "VFP pop" : first <= 0xeb ? "stack add 32-bit" : first === 0xec || first === 0xed
        ? "register pop 16-bit" : first === 0xee ? "Microsoft-specific" : first === 0xef
          ? "load LR" : first === 0xf5 || first === 0xf6 ? "VFP pop extended" :
            first <= 0xfa ? "stack add extended" : first === 0xfb || first === 0xfc ? "NOP" :
              first === 0xfd || first === 0xfe ? "end with NOP" : first === 0xff ? "end" : "unknown";
  summary.opcodeCounts[name] = (summary.opcodeCounts[name] ?? 0) + 1;
  if (first <= 0x7f) {
    summary.stackAdjustments.push(first * 4);
    return 1;
  }
  if (first <= 0xbf || first === 0xec || first === 0xed) {
    if (second == null) return 0;
    const mask = first <= 0xbf ? ((first & 0x3f) << 8) | second :
      ((first & 1) << 8) | second;
    summary.integerRegisterPopCount += popCount(mask & 0x1fff);
    if ((mask & 0x2000) !== 0) summary.returnAddressLoads += 1;
    return 2;
  }
  if (first <= 0xcf) {
    summary.framePointerRestores += 1;
    return 1;
  }
  if (first <= 0xdf) {
    summary.integerRegisterPopCount += (first & 3) + 1 + ((first & 4) !== 0 ? 1 : 0);
    if ((first & 4) !== 0) summary.returnAddressLoads += 1;
    return 1;
  }
  if (first <= 0xe7) {
    summary.floatingRegisterPopCount += (first & 7) + 1;
    return 1;
  }
  if (first <= 0xeb || first === 0xf7 || first === 0xf9) {
    if (second == null || ((first === 0xf7 || first === 0xf9) && codes[offset + 2] == null)) return 0;
    const size = first <= 0xeb ? 2 : 3;
    const amount = first <= 0xeb ? ((first & 3) << 8) | second! :
      (second! << 8) | codes[offset + 2]!;
    summary.stackAdjustments.push(amount * 4);
    return size;
  }
  if (first === 0xef) {
    if (second == null) return 0;
    if (second! > 0x0f) return -1;
    summary.returnAddressLoads += 1;
    marker(summary, "LR post-increment load");
    return 2;
  }
  if (first === 0xee) {
    if (second == null) return 0;
    if (second! > 0x0f) return -1;
    marker(summary, "Microsoft-specific operation");
    return 2;
  }
  if (first === 0xf5 || first === 0xf6) {
    if (second == null) return 0;
    const start = (second >>> 4) + (first === 0xf6 ? 16 : 0);
    const end = (second & 15) + (first === 0xf6 ? 16 : 0);
    if (end < start) return -1;
    summary.floatingRegisterPopCount += end - start + 1;
    return 2;
  }
  if (first === 0xf8 || first === 0xfa) {
    if (second == null || codes[offset + 2] == null || codes[offset + 3] == null) return 0;
    const amount = (second! << 16) | (codes[offset + 2]! << 8) | codes[offset + 3]!;
    summary.stackAdjustments.push(amount * 4);
    return 4;
  }
  if (first === 0xfb || first === 0xfc) {
    marker(summary, "NOP");
    return 1;
  }
  if (first === 0xfd || first === 0xfe) {
    marker(summary, "end with NOP");
    return 1;
  }
  if (first === 0xff) {
    marker(summary, "end");
    return 1;
  }
  summary.unknownOpcodeCount += 1;
  return -1;
};

/** Decode the bounded code pool once, stopping on unknown or malformed instruction layouts. */
export const summarizeArmntOpcodes = (codes: Uint8Array): ArmntOpcodeSummary => {
  const summary = createSummary();
  let terminated = false;
  for (let offset = 0; offset < codes.length;) {
    const consumed = decodeOne(codes, offset, summary);
    if (consumed <= 0) {
      summary.complete = false;
      if (consumed === 0) summary.unknownOpcodeCount += 1;
      break;
    }
    if (codes[offset] === 0xff || codes[offset] === 0xfd || codes[offset] === 0xfe) {
      terminated = true;
      break;
    }
    offset += consumed;
  }
  if (codes.length > 0 && !terminated) summary.complete = false;
  return summary;
};

/** Decode each declared sequence once; repeated scope starts represent shared tails. */
export const summarizeArmntOpcodeSequences = (
  codes: Uint8Array, sequenceStarts: number[]
): ArmntOpcodeSummary => {
  const combined = createSummary();
  for (const start of [...new Set(sequenceStarts)]) {
    if (!Number.isInteger(start) || start < 0 || start >= codes.length) {
      combined.complete = false;
      continue;
    }
    const sequence = summarizeArmntOpcodes(codes.subarray(start));
    for (const [name, count] of Object.entries(sequence.opcodeCounts)) {
      combined.opcodeCounts[name] = (combined.opcodeCounts[name] ?? 0) + count;
    }
    combined.instructionCount += sequence.instructionCount;
    combined.stackAdjustments.push(...sequence.stackAdjustments);
    combined.integerRegisterPopCount += sequence.integerRegisterPopCount;
    combined.floatingRegisterPopCount += sequence.floatingRegisterPopCount;
    combined.framePointerRestores += sequence.framePointerRestores;
    combined.returnAddressLoads += sequence.returnAddressLoads;
    combined.unknownOpcodeCount += sequence.unknownOpcodeCount;
    for (const [name, count] of Object.entries(sequence.specialMarkers)) {
      combined.specialMarkers[name] = (combined.specialMarkers[name] ?? 0) + count;
    }
    combined.complete &&= sequence.complete;
  }
  return combined;
};
