import type * as Iced from "iced-x86-disasm";
import type { Amd64PrologCheck, Amd64PrologDescription } from "./prolog-types.js";
import { Amd64PrologMachine } from "./prolog-machine.js";
import { checkAmd64PrologUnwind } from "./prolog-unwind.js";
import { checkAmd64Epilog } from "./prolog-epilog.js";
import { PE_RVA_EXCLUSIVE_LIMIT } from "../../layout/rva-limits.js";

const limitation = (reason: string): Amd64PrologCheck => ({ issues: [], limitations: [reason] });

const metadataLimitation = (description: Amd64PrologDescription): string | undefined => {
  if (description.version !== 1 && description.version !== 2) return "unwind-version";
  if (!description.complete || description.flags & ~7) return "invalid-unwind";
  if (description.flags & 4) return "chained-unwind";
  if ((description.frameRegister !== 0) !==
    description.operations.some(operation => operation.opcode === "SET_FPREG")) return "invalid-unwind";
  if (description.operations.some(operation => operation.opcode === "PUSH_MACHFRAME")) {
    return "machine-frame";
  }
  if (description.operations.some(operation => "register" in operation &&
    operation.register === 4 && !operation.opcode.includes("XMM"))) return "stack-register-save";
  if (description.operations.some(operation => operation.codeOffset === 0)) return "entry-unwind-state";
  if (!Number.isInteger(description.prologSize) || description.prologSize < 0 ||
    description.prologSize > 255) return "invalid-unwind";
  if (description.operations.some(operation => operation.codeOffset > description.prologSize)) {
    return "unwind-operation-range";
  }
  return undefined;
};

export class Amd64PrologChecker {
  readonly factory: Iced.InstructionInfoFactory;
  constructor(readonly iced: typeof Iced) { this.factory = new iced.InstructionInfoFactory(); }
  free(): void { this.factory.free(); }
  check(bytes: Uint8Array, description: Amd64PrologDescription,
    beginRva = 0, endRva = PE_RVA_EXCLUSIVE_LIMIT): Amd64PrologCheck {
    if (!Number.isSafeInteger(beginRva) || beginRva < 0 || beginRva >= PE_RVA_EXCLUSIVE_LIMIT) {
      return limitation("invalid-function-range");
    }
    const unsupported = metadataLimitation(description);
    if (unsupported) return limitation(unsupported);
    if (bytes.length < description.prologSize) return limitation("unreadable-code");
    const decoder = new this.iced.Decoder(64, bytes, this.iced.DecoderOptions.None);
    decoder.ip = BigInt(beginRva);
    const instruction = new this.iced.Instruction();
    const result: Amd64PrologCheck = { issues: [], limitations: [] };
    try { this.decode(decoder, instruction, description, result, bytes, beginRva, endRva); }
    finally { instruction.free(); decoder.free(); }
    result.limitations = [...new Set(result.limitations)];
    return result;
  }
  private decode(decoder: Iced.Decoder, instruction: Iced.Instruction,
    description: Amd64PrologDescription, result: Amd64PrologCheck,
    bytes: Uint8Array, begin: number, end: number): void {
    const machine = new Amd64PrologMachine(this.iced, this.factory);
    const seen = new Set<number>();
    while (decoder.position < description.prologSize) {
      decoder.decodeOut(instruction);
      if (!this.validInstruction(instruction, decoder.position, description.prologSize, result)) return;
      const effect = machine.step(instruction);
      if (effect.before?.kind === "stack" && effect.after?.kind === "stack" &&
        effect.after.offset > effect.before.offset) {
        result.limitations.push("stack-restoration");
        return;
      }
      seen.add(decoder.position);
      const checkpoint = checkAmd64PrologUnwind(machine, description, decoder.position, instruction);
      if (checkpoint.issues.length) {
        if (begin + decoder.position >= end) {
          result.limitations.push("function-end");
          return;
        }
        const epilog = checkAmd64Epilog(machine, description,
          bytes.subarray(decoder.position), begin + decoder.position, begin, end);
        if (epilog !== "not-epilog") {
          result.limitations.push(epilog === "matching" ? "epilog-in-prolog" : "epilog-state-unknown");
          return;
        }
      }
      for (const issue of checkpoint.issues) {
        if (!result.issues.some(other => other.code === issue.code && other.expected === issue.expected)) {
          result.issues.push(issue);
        }
      }
      result.limitations.push(...checkpoint.limitations);
      const flow = instruction.flowControl;
      if (flow !== this.iced.FlowControl.Next && flow !== this.iced.FlowControl.Call &&
        flow !== this.iced.FlowControl.IndirectCall) {
        result.limitations.push("control-flow");
        return;
      }
    }
    for (const operation of description.operations) {
      if (!seen.has(operation.codeOffset)) result.issues.push({ code: "operation-boundary",
        offset: operation.codeOffset, expected: operation.opcode });
    }
  }
  private validInstruction(instruction: Iced.Instruction, end: number,
    size: number, result: Amd64PrologCheck): boolean {
    if (instruction.code === this.iced.Code.INVALID) {
      // A decoder failure also covers newer ISA encodings (e.g. APX/REX2).
      // It cannot establish a disagreement between code and unwind metadata.
      result.limitations.push("undecodable-instruction");
      return false;
    }
    if (end > size) {
      result.limitations.push("prolog-boundary");
      return false;
    }
    return true;
  }
}
