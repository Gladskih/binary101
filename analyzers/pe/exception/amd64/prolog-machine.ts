import type * as Iced from "iced-x86-disasm";

export type PrologValue =
  | { kind: "stack" | "constant"; offset: bigint }
  | { kind: "original"; register: number }
  | { kind: "missing-save" };

export interface PrologInstructionEffect {
  before: PrologValue | undefined;
  after: PrologValue | undefined;
}

type PrologStore = { address: PrologValue | undefined; value: PrologValue | undefined; size: number };

/** Only affine stack addresses, exact constants and original register values are retained.
 * Every other write invalidates the value, including implicit and partial-register writes.
 * iced's register-use contract: https://github.com/icedland/iced/tree/master/src/rust/iced-x86-js
 */
export class Amd64PrologMachine {
  readonly values = new Map<number, PrologValue>();
  readonly memory = new Map<bigint, { size: number; value: PrologValue | undefined }>();
  uncertainMemory = false;
  constructor(readonly iced: typeof Iced, readonly factory: Iced.InstructionInfoFactory) {
    for (let index = 0; index < 16; index++) {
      this.values.set(iced.Register.RAX + index,
        { kind: "original", register: iced.Register.RAX + index });
      this.values.set(iced.Register.ZMM0 + index,
        { kind: "original", register: iced.Register.ZMM0 + index });
    }
    this.values.set(iced.Register.RSP, { kind: "stack", offset: 0n });
  }
  value(register: number): PrologValue | undefined {
    return this.values.get(this.iced.RegisterExt.fullRegister(register));
  }
  address(instruction: Iced.Instruction): PrologValue | undefined {
    const { Register, RegisterExt, Mnemonic } = this.iced;
    if (instruction.mnemonic !== Mnemonic.Lea &&
      (instruction.segmentPrefix === Register.FS || instruction.segmentPrefix === Register.GS)) {
      return undefined;
    }
    if (instruction.memoryIndex !== Register.None ||
      RegisterExt.size(instruction.memoryBase) !== 8) return undefined;
    const base = this.value(instruction.memoryBase);
    return base?.kind === "stack" ? { kind: "stack", offset: base.offset +
      BigInt.asIntN(64, instruction.memoryDisplacement) } : undefined;
  }
  operand(instruction: Iced.Instruction, index: number): PrologValue | undefined {
    const { OpKind } = this.iced;
    const kind = instruction.opKind(index);
    if (kind === OpKind.Register) return this.value(instruction.opRegister(index));
    // iced immediate kinds are contiguous, from Immediate8 through Immediate32to64.
    // https://docs.rs/iced-x86/latest/iced_x86/enum.OpKind.html
    if (kind >= OpKind.Immediate8 && kind <= OpKind.Immediate32to64) {
      return { kind: "constant", offset: BigInt.asIntN(64, instruction.immediate(index)) };
    }
    return undefined;
  }
  private assignedValue(instruction: Iced.Instruction): PrologValue | undefined {
    const { Mnemonic, RegisterExt } = this.iced;
    const source = this.operand(instruction, 1);
    const size = RegisterExt.size(instruction.op0Register);
    if (instruction.mnemonic === Mnemonic.Mov) {
      if (size === 8) return source;
      if (size === 4 && source?.kind === "constant") {
        return { kind: "constant", offset: BigInt.asUintN(32, source.offset) };
      }
    }
    if (size !== 8) return undefined;
    if (instruction.mnemonic === Mnemonic.Lea) return this.address(instruction);
    if (instruction.mnemonic !== Mnemonic.Add && instruction.mnemonic !== Mnemonic.Sub) {
      return undefined;
    }
    const target = this.value(instruction.op0Register);
    if (!target || (target.kind !== "stack" && target.kind !== "constant") ||
      source?.kind !== "constant") return undefined;
    return { kind: target.kind, offset: target.offset +
      (instruction.mnemonic === Mnemonic.Sub ? -source.offset : source.offset) };
  }
  private invalidate(instruction: Iced.Instruction): void {
    const { OpAccess, RegisterExt, Mnemonic } = this.iced;
    const info = this.factory.info(instruction);
    try {
      this.invalidateMemory(instruction, info);
      // The upstream binding declares any[] but returns UsedRegister wrappers.
      // Isolate that documented WASM contract here.
      const usages = info.usedRegisters() as Iced.UsedRegister[];
      for (const usage of usages) {
        try {
          if (usage.access === OpAccess.Write || usage.access === OpAccess.CondWrite ||
            usage.access === OpAccess.ReadWrite || usage.access === OpAccess.ReadCondWrite) {
            const register = RegisterExt.fullRegister(usage.register);
            // VZEROUPPER leaves the nonvolatile low 128-bit lanes intact.
            if (instruction.mnemonic === Mnemonic.Vzeroupper && RegisterExt.isZMM(register)) continue;
            this.values.delete(register);
          }
        } finally { usage.free(); }
      }
    } finally { info.free(); }
  }
  private invalidateMemory(instruction: Iced.Instruction, info: Iced.InstructionInfo): void {
    const { OpAccess, Register, RegisterExt, MemorySizeExt } = this.iced;
    // Like usedRegisters(), the WASM binding returns typed wrappers as any[].
    const memories = info.usedMemory() as Iced.UsedMemory[];
    for (const memory of memories) {
      try {
        if (![OpAccess.Write, OpAccess.ReadWrite, OpAccess.CondWrite, OpAccess.ReadCondWrite]
          .includes(memory.access)) continue;
        const base = this.value(memory.base);
        const size = MemorySizeExt.size(memory.memorySize);
        if (base?.kind === "stack" && RegisterExt.size(memory.base) === 8 &&
          memory.index === Register.None && memory.segment !== Register.FS &&
          memory.segment !== Register.GS && !instruction.hasRepPrefix &&
          !instruction.hasRepnePrefix && size > 0) {
          this.write(base.offset + BigInt.asIntN(64, memory.displacement), size, undefined);
        } else { this.memory.clear(); this.uncertainMemory = true; }
      } finally { memory.free(); }
    }
  }
  private store(instruction: Iced.Instruction): PrologStore | undefined {
    const { Mnemonic, OpKind, MemorySizeExt } = this.iced;
    if (instruction.opCount !== 2 || instruction.op0Kind !== OpKind.Memory ||
      instruction.op1Kind !== OpKind.Register || instruction.hasOpMask) return undefined;
    if (![Mnemonic.Mov, Mnemonic.Movaps, Mnemonic.Movups, Mnemonic.Movdqa, Mnemonic.Movdqu,
      Mnemonic.Vmovaps, Mnemonic.Vmovups, Mnemonic.Vmovdqa, Mnemonic.Vmovdqu,
      Mnemonic.Vmovdqa32, Mnemonic.Vmovdqa64, Mnemonic.Vmovdqu8, Mnemonic.Vmovdqu16,
      Mnemonic.Vmovdqu32, Mnemonic.Vmovdqu64].includes(instruction.mnemonic)) return undefined;
    return { address: this.address(instruction),
    value: this.operand(instruction, 1), size: MemorySizeExt.size(instruction.memorySize) };
  }
  step(instruction: Iced.Instruction): PrologInstructionEffect {
    const { Register, OpKind, Mnemonic, FlowControl } = this.iced;
    const before = this.value(Register.RSP);
    const store = this.store(instruction);
    const assigned = instruction.op0Kind === OpKind.Register && instruction.opCount >= 2
      ? this.assignedValue(instruction) : undefined;
    const pushed = instruction.mnemonic === Mnemonic.Push ? this.operand(instruction, 0) : undefined;
    this.invalidate(instruction);
    if (instruction.op0Kind === OpKind.Register && assigned) {
      this.values.set(this.iced.RegisterExt.fullRegister(instruction.op0Register), assigned);
    }
    if (instruction.mnemonic === Mnemonic.Push && before?.kind === "stack") {
      this.values.set(Register.RSP, { kind: "stack", offset:
        before.offset + BigInt(instruction.stackPointerIncrement) });
      this.write(before.offset + BigInt(instruction.stackPointerIncrement),
        -instruction.stackPointerIncrement, pushed);
    }
    if (store?.address?.kind === "stack") this.write(store.address.offset, store.size, store.value);
    if (instruction.flowControl === FlowControl.Call ||
      instruction.flowControl === FlowControl.IndirectCall) this.finishCall(before);
    return { before, after: this.value(Register.RSP) };
  }
  private finishCall(stack: PrologValue | undefined): void {
    const { Register } = this.iced;
    // Windows x64 ABI: calls preserve RSP and nonvolatile registers; volatile values
    // (including RAX across an unidentified stack-probe helper) become unknown.
    // https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention
    for (const register of [Register.RAX, Register.RCX, Register.RDX,
      Register.R8, Register.R9, Register.R10, Register.R11]) this.values.delete(register);
    for (let index = 0; index < 6; index++) this.values.delete(Register.ZMM0 + index);
    if (stack) this.values.set(Register.RSP, stack);
    if (stack?.kind === "stack") this.write(stack.offset - 8n, 40, undefined);
    else { this.memory.clear(); this.uncertainMemory = true; }
  }
  write(address: bigint, size: number, value: PrologValue | undefined): void {
    for (const [offset, saved] of this.memory) {
      if (offset < address + BigInt(size) && address < offset + BigInt(saved.size)) {
        this.memory.delete(offset);
      }
    }
    this.memory.set(address, { size, value });
  }
}
