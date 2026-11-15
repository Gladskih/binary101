import type { IcedInstructionObject, IcedX86Module } from "./disassembly-iced.js";

type DirectMemoryBranch = { kind: "call" | "jump"; address: bigint };

const branchKind = (iced: IcedX86Module,
  instruction: IcedInstructionObject): DirectMemoryBranch["kind"] | null => {
  if (instruction.isCallNearIndirect) {
    return !instruction.isJmpNearIndirect &&
      instruction.flowControl === iced.FlowControl["IndirectCall"] ? "call" : null;
  }
  return instruction.isJmpNearIndirect &&
    instruction.flowControl === iced.FlowControl["IndirectBranch"] ? "jump" : null;
};

export const getX86DirectMemoryBranch = (iced: IcedX86Module,
  instruction: IcedInstructionObject): DirectMemoryBranch | null => {
  const kind = branchKind(iced, instruction);
  if (kind == null || instruction.op0Kind !== iced.OpKind["Memory"]) return null;
  const noRegister = iced.Register?.["None"];
  if (noRegister == null || instruction.memoryIndex !== noRegister) return null;
  // FS/GS add a runtime segment base; the displacement alone does not identify an image slot.
  // Intel SDM Vol. 1, 3.3.7.1; iced resolves RIP/EIP-relative memory addresses.
  // https://docs.rs/iced-x86/latest/iced_x86/struct.Instruction.html#method.ip_rel_memory_address
  if (instruction.segmentPrefix != null &&
    (instruction.segmentPrefix === iced.Register?.["FS"] ||
      instruction.segmentPrefix === iced.Register?.["GS"])) return null;
  const relative = instruction.memoryBase === iced.Register?.["EIP"] ||
    instruction.memoryBase === iced.Register?.["RIP"];
  if (instruction.isIpRelMemoryOperand !== relative ||
    (!relative && instruction.memoryBase !== noRegister)) return null;
  return { kind, address: relative ? instruction.ipRelMemoryAddress : instruction.memoryDisplacement };
};
