import type { Amd64UnwindOperation, Amd64UnwindOperationBody } from "./unwind-v12-types.js";

// Microsoft x64 exception handling, "Unwind operation code" and "Operation info".
// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#struct-unwind_code
export const amd64UnwindOperationSlots = (opcode: number, info: number): number => {
  if (opcode === 1) return info === 0 ? 2 : 3;
  if (opcode === 4 || opcode === 8) return 2;
  if (opcode === 5 || opcode === 9) return 3;
  return 1;
};

type SavedRegisterOperation = Extract<Amd64UnwindOperationBody, { displacement: number }>;

const SAVE_OPCODES = new Map<number, SavedRegisterOperation["opcode"]>([[4, "SAVE_NONVOL"], [5, "SAVE_NONVOL_FAR"],
  [8, "SAVE_XMM128"], [9, "SAVE_XMM128_FAR"]] as const);

const saveOperation = (view: DataView, offset: number, opcode: number, register: number): Amd64UnwindOperationBody => {
  const displacement = opcode === 5 || opcode === 9 ? view.getUint32(offset + 2, true)
    : view.getUint16(offset + 2, true) * (opcode === 8 ? 16 : 8);
  return { opcode: SAVE_OPCODES.get(opcode)!, register, displacement };
};

const operationBody = (view: DataView, offset: number, opcode: number, info: number): Amd64UnwindOperationBody => {
  switch (opcode) {
    case 0: return { opcode: "PUSH_NONVOL", register: info };
    case 1: return { opcode: "ALLOC_LARGE", size: info === 0
      ? view.getUint16(offset + 2, true) * 8 : view.getUint32(offset + 2, true) };
    case 2: return { opcode: "ALLOC_SMALL", size: info * 8 + 8 };
    case 3: return { opcode: "SET_FPREG" };
    case 10: return { opcode: "PUSH_MACHFRAME", size: info === 0 ? 40 : 48 };
    default: return saveOperation(view, offset, opcode, info);
  }
};

const validOperationInfo = (opcode: number, info: number): boolean => {
  if (opcode === 1 || opcode === 10) return info <= 1;
  return opcode !== 3 || info === 0;
};

/** Decode one complete operation; callers must stop at an unknown encoding. */
export const decodeAmd64UnwindOperation = (view: DataView, index: number,
  issues: string[]): Amd64UnwindOperation | null => {
  const offset = index * 2;
  if (!Number.isInteger(index) || index < 0 || offset + 2 > view.byteLength) {
    issues.push("AMD64 unwind operation header is out of bounds.");
    return null;
  }
  const opcode = view.getUint8(offset + 1) & 15;
  const info = view.getUint8(offset + 1) >>> 4;
  if (![0, 1, 2, 3, 10].includes(opcode) && !SAVE_OPCODES.has(opcode)) {
    issues.push(`AMD64 unwind opcode ${opcode} is unknown or reserved; remaining operations are not decoded.`);
    return null;
  }
  if (!validOperationInfo(opcode, info)) {
    issues.push(`AMD64 unwind opcode ${opcode} has reserved OpInfo ${info}.`);
    return null;
  }
  if (offset + amd64UnwindOperationSlots(opcode, info) * 2 > view.byteLength) {
    issues.push("AMD64 unwind operation operands are truncated.");
    return null;
  }
  return { codeOffset: view.getUint8(offset), ...operationBody(view, offset, opcode, info) };
};
