import type { Amd64PrologMachine, PrologValue } from "./prolog-machine.js";
import type { Amd64PrologCheck, Amd64PrologDescription } from "./prolog-types.js";
import type { Instruction } from "iced-x86-disasm";

const stackOffset = (value: PrologValue | undefined): bigint | undefined =>
  value?.kind === "stack" ? value.offset : undefined;

/** Replay applicable unwind operations at an instruction boundary. SAVE uses
 * FrameBase; PUSH/ALLOC advance virtual RSP. SAVE directives may describe earlier
 * stores to the caller's home area.
 * https://github.com/dotnet/runtime/blob/main/src/coreclr/unwinder/amd64/unwinder.cpp
 * https://learn.microsoft.com/en-us/cpp/assembler/masm/dot-savereg
 */
export const checkAmd64PrologUnwind = (machine: Amd64PrologMachine,
  description: Amd64PrologDescription, offset: number, instruction: Instruction): Amd64PrologCheck => {
  const { Register, RegisterExt } = machine.iced;
  const result: Amd64PrologCheck = { issues: [], limitations: [] };
  const restored = new Map<number, PrologValue | undefined>();
  const active = description.operations.filter(operation => operation.codeOffset <= offset);
  let stack = stackOffset(machine.value(Register.RSP));
  const frameSet = active.some(operation => operation.opcode === "SET_FPREG");
  const frameBase = frameSet ? stackOffset(machine.value(Register.RAX + description.frameRegister)) : stack;
  const base = frameBase === undefined ? undefined
    : frameBase - (frameSet ? BigInt(description.frameOffset) : 0n);
  for (const operation of active) {
    switch (operation.opcode) {
      case "ALLOC_SMALL": case "ALLOC_LARGE":
        if (stack !== undefined) stack += BigInt(operation.size);
        break;
      case "SET_FPREG": stack = base; break;
      case "PUSH_NONVOL":
        restored.set(Register.RAX + operation.register, readSaved(machine, stack, 8, result));
        if (stack !== undefined) stack += 8n;
        break;
      case "SAVE_NONVOL": case "SAVE_NONVOL_FAR":
        restored.set(Register.RAX + operation.register,
          readSaved(machine, base === undefined ? undefined : base + BigInt(operation.displacement), 8, result));
        break;
      case "SAVE_XMM128": case "SAVE_XMM128_FAR":
        restored.set(RegisterExt.fullRegister(Register.XMM0 + operation.register),
          readSaved(machine, base === undefined ? undefined : base + BigInt(operation.displacement), 16, result));
        break;
    }
  }
  if (stack === undefined) result.limitations.push("unknown-stack-effect");
  else if (stack !== 0n) result.issues.push({
    code: active.length ? "operation-mismatch" : "undescribed-stack", offset,
    expected: "recover entry RSP", actual: `${instruction}; recovered RSP = entry RSP ${stack}`
  });
  // Only the registers asserted by these unwind operations are checked. Internal
  // Go/JIT/assembly routines can use a different calling convention.
  for (const register of restored.keys()) {
    compareRegister(machine, restored, register, offset, instruction, result);
  }
  return result;
};

const readSaved = (machine: Amd64PrologMachine, address: bigint | undefined,
  size: number, result: Amd64PrologCheck): PrologValue | undefined => {
  if (address === undefined) return undefined;
  const saved = machine.memory.get(address);
  if (!saved || saved.size < size) {
    for (const [offset, write] of machine.memory) {
      if (!write.value && offset < address + BigInt(size) && address < offset + BigInt(write.size)) {
        return undefined;
      }
    }
    if (machine.uncertainMemory) return undefined;
    // No matching save was observed at this known address.
    return { kind: "missing-save" };
  }
  if (!saved.value) result.limitations.push("unknown-saved-value");
  return saved.value;
};

const compareRegister = (machine: Amd64PrologMachine,
  restored: Map<number, PrologValue | undefined>, register: number,
  offset: number, instruction: Instruction, result: Amd64PrologCheck): void => {
  const value = restored.has(register) ? restored.get(register) : machine.value(register);
  if (!value) result.limitations.push("unknown-register-value");
  else if (value.kind !== "original" || value.register !== register) {
    result.issues.push({ code: "operation-mismatch", offset,
      expected: `recover ${machine.iced.RegisterExt.isZMM(register)
        ? `XMM${machine.iced.RegisterExt.number(register)}` : machine.iced.Register[register]}`,
      actual: `${instruction}; original register value is not recovered` });
  }
};
