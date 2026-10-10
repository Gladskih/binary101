import { GC_INFO_BASES } from "./gc-info-wire-format.js";

export class GcInfoBitsFixture {
  readonly bits: number[] = [];

  // GCInfo fields are written least-significant bit first; variable integers use
  // low payload groups followed by one continuation bit per group.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/gcinfo/gcinfoencoder.cpp
  field(value: number, width: number): this {
    for (let bit = 0; bit < width; bit++) this.bits.push(Math.floor(value / 2 ** bit) & 1);
    return this;
  }

  repeatedField(value: number, width: number, count: number): this {
    for (let index = 0; index < count; index++) this.field(value, width);
    return this;
  }

  slimX64V4Header(codeLength: number): this {
    return this.field(0, 1).field(0, 1).unsigned(codeLength, GC_INFO_BASES.codeLength);
  }

  slimX64V4HeaderWithFrameRegister(codeLength: number): this {
    return this.field(0, 1).field(1, 1).unsigned(codeLength, GC_INFO_BASES.codeLength);
  }

  slimX64V3Header(returnKind: number, codeLength: number): this {
    return this.field(0, 1).field(0, 1)
      .field(returnKind, GC_INFO_BASES.slimV3ReturnKind)
      .unsigned(codeLength, GC_INFO_BASES.codeLength);
  }

  fatX64V4Header(flags: number, codeLength: number): this {
    return this.field(1, 1).field(flags, GC_INFO_BASES.headerFlags)
      .unsigned(codeLength, GC_INFO_BASES.codeLength);
  }

  fatX64V3Header(flags: number, returnKind: number, codeLength: number): this {
    return this.field(1, 1).field(flags, GC_INFO_BASES.headerFlags)
      .field(returnKind, GC_INFO_BASES.fatV3ReturnKind)
      .unsigned(codeLength, GC_INFO_BASES.codeLength);
  }

  x64CookieValidityRange(codeLength: number, startOffset: number, endOffset: number): this {
    return this.unsigned(startOffset - 1, 5).unsigned(codeLength - endOffset, 3);
  }

  x64PrologValidityStart(startOffset: number): this {
    return this.unsigned(startOffset - 1, 5);
  }

  x64StackOffset(offsetBytes: number): this {
    return this.signed(offsetBytes / 8, GC_INFO_BASES.signedStackOffset);
  }

  x64FrameLayout(stackBaseRegister: number, editAndContinueBytes: number,
    reversePInvokeOffset: number, outgoingStackBytes: number): this {
    return this.unsigned(stackBaseRegister, GC_INFO_BASES.stackBaseRegister)
      .unsigned(editAndContinueBytes, GC_INFO_BASES.editAndContinueBytes)
      .x64StackOffset(reversePInvokeOffset)
      .unsigned(outgoingStackBytes / 8, GC_INFO_BASES.outgoingStackUnits);
  }

  x64OutgoingStackBytes(bytes: number): this {
    return this.unsigned(bytes / 8, GC_INFO_BASES.outgoingStackUnits);
  }

  x64SlotCounts(registers: number, stackSlots: number, untrackedSlots: number): this {
    this.field(registers > 0 ? 1 : 0, 1);
    if (registers) this.unsigned(registers, GC_INFO_BASES.registerCount);
    this.field(stackSlots || untrackedSlots ? 1 : 0, 1);
    if (stackSlots || untrackedSlots) {
      this.unsigned(stackSlots, GC_INFO_BASES.stackCount)
        .unsigned(untrackedSlots, GC_INFO_BASES.untrackedCount);
    }
    return this;
  }

  x64Register(register: number, flags: number): this {
    return this.unsigned(register, GC_INFO_BASES.register).field(flags, 2);
  }

  x64RegisterDelta(delta: number): this {
    return this.unsigned(delta - 1, GC_INFO_BASES.registerDelta);
  }

  x64StackSlot(base: number, offsetBytes: number, flags: number): this {
    return this.field(base, 2).x64StackOffset(offsetBytes).field(flags, 2);
  }

  x64StackSlotDelta(base: number, offsetBytes: number): this {
    return this.field(base, 2).unsigned(offsetBytes / 8, GC_INFO_BASES.stackSlotDelta);
  }

  safePointCount(count: number): this {
    return this.unsigned(count, GC_INFO_BASES.safePointCount);
  }

  interruptibleRangeCount(count: number): this {
    return this.unsigned(count, GC_INFO_BASES.interruptibleRangeCount);
  }

  safePointOffsets(codeLength: number, ...offsets: number[]): this {
    const width = Math.ceil(Math.log2(codeLength));
    for (const offset of offsets) this.field(offset, width);
    return this;
  }

  x64InterruptibleRange(previousEnd: number, startOffset: number, endOffset: number): this {
    return this.unsigned(startOffset - previousEnd, GC_INFO_BASES.transitionOffset)
      .unsigned(endOffset - startOffset - 1, GC_INFO_BASES.transitionOffset);
  }

  directSafePointStates(trackedSlots: number, ...liveSlotSets: number[][]): this {
    this.field(0, 1);
    for (const liveSlots of liveSlotSets) {
      this.field(liveSlots.reduce((bits, slot) => bits | 2 ** slot, 0), trackedSlots);
    }
    return this;
  }

  rawLiveSlots(trackedSlots: number, liveSlots: number[]): this {
    return this.field(0, 1)
      .field(liveSlots.reduce((bits, slot) => bits | 2 ** slot, 0), trackedSlots);
  }

  runLengthLiveSlots(skipBase: 2 | 4, initialDeadSlots: number,
    ...alternatingRunLengths: number[]): this {
    const runBase = skipBase === 2 ? 4 : 2;
    this.field(1, 1).field(skipBase === 2 ? 1 : 0, 1).unsigned(initialDeadSlots, skipBase);
    alternatingRunLengths.forEach((length, index) =>
      this.unsigned(length - 1, index % 2 ? skipBase : runBase));
    return this;
  }

  sharedIndirectSafePointState(trackedSlots: number, safePointCount: number,
    liveSlots: number[]): this {
    this.field(1, 1).unsigned(0, GC_INFO_BASES.safePointPointerWidth);
    this.repeatedField(0, 1, safePointCount);
    this.repeatedField(0, (8 - this.bits.length % 8) % 8, 1);
    this.field(0, 1).field(liveSlots.reduce((bits, slot) => bits | 2 ** slot, 0), trackedSlots);
    return this;
  }

  transitionTable(pointerWidth: number, ...chunkPointers: number[]): this {
    this.unsigned(pointerWidth, GC_INFO_BASES.transitionPointerWidth);
    for (const pointer of chunkPointers) this.field(pointer, pointerWidth);
    const padding = (8 - this.bits.length % 8) % 8;
    if (padding) this.field(0, padding);
    return this;
  }

  transitionChunkLiveSlots(trackedSlots: number, slots: number[]): this {
    return this.directSafePointStates(trackedSlots, slots);
  }

  transitionChunkSlot(finalLive: 0 | 1, ...offsets: number[]): this {
    this.field(finalLive, 1);
    for (const offset of offsets) {
      this.field(1, 1).field(offset, GC_INFO_BASES.transitionOffset);
    }
    this.field(0, 1);
    return this;
  }

  unsigned(value: number, base: number): this {
    let rest = value;
    do {
      const chunk = rest % 2 ** base;
      rest = Math.floor(rest / 2 ** base);
      this.field(chunk + (rest ? 2 ** base : 0), base + 1);
    } while (rest);
    return this;
  }

  signed(value: number, base: number): this {
    let rest = BigInt(value);
    let more: boolean;
    do {
      const chunk = Number(BigInt.asUintN(base, rest));
      rest >>= BigInt(base);
      more = !(rest === 0n && chunk < 2 ** (base - 1) ||
        rest === -1n && chunk >= 2 ** (base - 1));
      this.field(chunk + (more ? 2 ** base : 0), base + 1);
    } while (more);
    return this;
  }

  bytes(): Uint8Array {
    const bytes = new Uint8Array(Math.ceil(this.bits.length / 8));
    this.bits.forEach((bit, index) => { bytes[Math.floor(index / 8)]! |= bit << (index & 7); });
    return bytes;
  }
}
