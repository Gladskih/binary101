import type { Amd64UnwindOperation, Amd64UnwindOpcode, Amd64UnwindOperationVisitor }
  from "./unwind-v12-types.js";

// Microsoft x64 exception handling, "Unwind operation code" and "Operation info".
// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#struct-unwind_code
export const amd64UnwindOperationSlots = (opcode: number, info: number): number => {
  if (opcode === 1) return info === 0 ? 2 : 3;
  if (opcode === 4 || opcode === 8) return 2;
  if (opcode === 5 || opcode === 9) return 3;
  return 1;
};

export const AMD64_UNWIND_OPERATION_NAMES = {
  0: "PUSH_NONVOL", 1: "ALLOC_LARGE", 2: "ALLOC_SMALL", 3: "SET_FPREG",
  4: "SAVE_NONVOL", 5: "SAVE_NONVOL_FAR", 8: "SAVE_XMM128", 9: "SAVE_XMM128_FAR", 10: "PUSH_MACHFRAME"
} as const;

const operationOperand = (view: DataView, offset: number, opcode: Amd64UnwindOpcode, info: number): number => {
  switch (opcode) {
    case 0: case 3: return 0;
    case 1: return info === 0 ? view.getUint16(offset + 2, true) * 8 : view.getUint32(offset + 2, true);
    case 2: return info * 8 + 8;
    case 10: return info === 0 ? 40 : 48;
    case 5: case 9: return view.getUint32(offset + 2, true);
    default: return view.getUint16(offset + 2, true) * (opcode === 8 ? 16 : 8);
  }
};

const operationRecord = (codeOffset: number, opcode: Amd64UnwindOpcode,
  info: number, operand: number): Amd64UnwindOperation => {
  switch (opcode) {
    case 0: return { codeOffset, opcode: "PUSH_NONVOL", register: info };
    case 1: case 2: return { codeOffset, opcode: AMD64_UNWIND_OPERATION_NAMES[opcode], size: operand };
    case 3: return { codeOffset, opcode: "SET_FPREG" };
    case 10: return { codeOffset, opcode: "PUSH_MACHFRAME", size: operand };
    default: return { codeOffset, opcode: AMD64_UNWIND_OPERATION_NAMES[opcode],
      register: info, displacement: operand };
  }
};

const validOperationInfo = (opcode: number, info: number): boolean => {
  if (opcode === 1 || opcode === 10) return info <= 1;
  // SET_FPREG ignores OpInfo; Microsoft producers also emit nonzero values.
  // https://github.com/dotnet/coreclr/blob/a9f3fc16483eecfc47fb79c362811d870be02249/src/vm/stublink.cpp#L1248
  return true;
};

const isKnownOpcode = (opcode: number): opcode is Amd64UnwindOpcode =>
  opcode <= 5 || opcode === 8 || opcode === 9 || opcode === 10;

/** Validate and emit one operation without allocating a transient record. */
export const visitAmd64UnwindOperation = (view: DataView, index: number,
  issues: string[], visitor: Amd64UnwindOperationVisitor): boolean => {
  const offset = index * 2;
  if (!Number.isInteger(index) || index < 0 || offset + 2 > view.byteLength) {
    issues.push("AMD64 unwind operation header is out of bounds.");
    return false;
  }
  const opcode = view.getUint8(offset + 1) & 15;
  const info = view.getUint8(offset + 1) >>> 4;
  if (!isKnownOpcode(opcode)) {
    issues.push(`AMD64 unwind opcode ${opcode} is unknown or reserved; remaining operations are not decoded.`);
    return false;
  }
  if (!validOperationInfo(opcode, info)) {
    issues.push(`AMD64 unwind opcode ${opcode} has reserved OpInfo ${info}.`);
    return false;
  }
  if (offset + amd64UnwindOperationSlots(opcode, info) * 2 > view.byteLength) {
    issues.push("AMD64 unwind operation operands are truncated.");
    return false;
  }
  visitor(view.getUint8(offset), opcode, info, operationOperand(view, offset, opcode, info));
  return true;
};

export const createAmd64UnwindOperationCollector = (
  operations: Amd64UnwindOperation[]
): Amd64UnwindOperationVisitor => (codeOffset, opcode, info, operand) => {
  operations.push(operationRecord(codeOffset, opcode, info, operand));
};

/** Decode one complete operation; callers must stop at an unknown encoding. */
export const decodeAmd64UnwindOperation = (view: DataView, index: number,
  issues: string[]): Amd64UnwindOperation | null => {
  const operations: Amd64UnwindOperation[] = [];
  visitAmd64UnwindOperation(view, index, issues, createAmd64UnwindOperationCollector(operations));
  return operations[0] ?? null;
};
