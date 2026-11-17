import type { Instruction } from "iced-x86-disasm";
import type { Amd64PrologMachine, PrologValue } from "./prolog-machine.js";
import type { Amd64PrologDescription } from "./prolog-types.js";

const isTailJump = (machine: Amd64PrologMachine, instruction: Instruction,
  bytes: Uint8Array, begin: number, end: number): boolean => {
  const { FlowControl } = machine.iced;
  if (instruction.flowControl === FlowControl.UnconditionalBranch) {
    return instruction.nearBranchTarget <= BigInt(begin) || instruction.nearBranchTarget >= BigInt(end);
  }
  // The system unwinder recognizes FF 25 or REX.W FF /4, including register
  // operands. REX.W is a deliberate tail-call marker, not just operand size.
  // https://github.com/dotnet/runtime/blob/main/src/coreclr/unwinder/amd64/unwinder.cpp
  const start = bytes[0] === 0xf2 ? 1 : 0;
  return instruction.isJmpNearIndirect && (bytes[start] === 0xff && bytes[start + 1] === 0x25 ||
    bytes[start]! >= 0x48 && bytes[start]! <= 0x4f && bytes[start + 1] === 0xff &&
    ((bytes[start + 2] ?? 0) & 0x38) === 0x20);
};

const restoresCaller = (machine: Amd64PrologMachine, description: Amd64PrologDescription,
  values: Map<number, PrologValue>, stack: bigint, offset: number): boolean => {
  if (stack !== 0n) return false;
  for (const [offset, saved] of machine.memory) {
    if (offset < 8n && offset + BigInt(saved.size) > 0n) return false;
  }
  for (const operation of description.operations) {
    if (offset < description.prologSize && operation.codeOffset > offset) continue;
    if (!("register" in operation)) continue;
    const register = operation.opcode.includes("XMM")
      ? machine.iced.Register.ZMM0 + operation.register : machine.iced.Register.RAX + operation.register;
    const value = values.get(register);
    if (value?.kind !== "original" || value.register !== register) return false;
  }
  return true;
};

/** Suppress a metadata-only counterexample when the current state is already in
 * a canonical, independently recoverable epilog. This also covers shrink-wrapped
 * returns inside SizeOfProlog; it does not claim to validate all function exits.
 * https://github.com/dotnet/runtime/blob/main/src/coreclr/unwinder/amd64/unwinder.cpp
 */
export const checkAmd64Epilog = (machine: Amd64PrologMachine,
  description: Amd64PrologDescription, bytes: Uint8Array,
  pc: number, begin: number, end: number): "matching" | "not-epilog" | "incomplete" => {
  const { Register, Mnemonic, OpKind } = machine.iced;
  const initial = machine.value(Register.RSP);
  if (initial?.kind !== "stack") return "incomplete";
  let stack = initial.offset;
  const values = new Map(machine.values);
  const decoder = new machine.iced.Decoder(64, bytes, machine.iced.DecoderOptions.None);
  decoder.ip = BigInt(pc);
  const instruction = new machine.iced.Instruction();
  let position = "adjustment";
  try {
    while (decoder.canDecode) {
      decoder.decodeOut(instruction);
      if (instruction.code === machine.iced.Code.INVALID &&
        decoder.lastError === machine.iced.DecoderError.NoMoreBytes) return "incomplete";
      // RET imm16 is also an epilog indicator in the Windows unwinder.
      if (instruction.mnemonic === Mnemonic.Ret || isTailJump(machine, instruction,
        bytes.subarray(decoder.position - instruction.length, decoder.position), begin, end)) {
        // Once Windows recognizes an epilog, metadata-only replay is not the
        // right oracle. A bad/opaque epilog state remains outside this prolog check.
        if (!restoresCaller(machine, description, values, stack, pc - begin)) return "incomplete";
        return machine.uncertainMemory ? "incomplete" : "matching";
      }
      if (position === "adjustment" && instruction.mnemonic === Mnemonic.Add &&
        instruction.op0Kind === OpKind.Register && instruction.op0Register === Register.RSP &&
        instruction.op1Kind >= OpKind.Immediate8 && instruction.op1Kind <= OpKind.Immediate32to64) {
        stack += BigInt.asIntN(64, instruction.immediate(1));
      } else if (position === "adjustment" && instruction.mnemonic === Mnemonic.Lea &&
        instruction.op0Register === Register.RSP && instruction.memoryIndex === Register.None &&
        instruction.memoryBase === Register.RAX + description.frameRegister && description.frameRegister !== 0) {
        const frame = values.get(instruction.memoryBase);
        if (frame?.kind !== "stack") return "incomplete";
        stack = frame.offset + BigInt.asIntN(64, instruction.memoryDisplacement);
      } else if (instruction.mnemonic === Mnemonic.Pop && instruction.op0Kind === OpKind.Register &&
        instruction.op0Register !== Register.RSP && machine.iced.RegisterExt.isGPR64(instruction.op0Register)) {
        const saved = machine.memory.get(stack);
        if (!saved?.value || saved.size < 8) return "incomplete";
        values.set(instruction.op0Register, saved.value);
        stack += 8n;
      } else return "not-epilog";
      position = "pops";
    }
    return pc + bytes.length < end ? "incomplete" : "not-epilog";
  } finally { instruction.free(); decoder.free(); }
};
