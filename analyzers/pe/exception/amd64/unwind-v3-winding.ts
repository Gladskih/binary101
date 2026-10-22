import type { Amd64WindingOperation } from "./unwind-v3-types.js";

type DecodedWinding = { operation: Amd64WindingOperation; byteLength: number };

// Variable-width low-bit prefixes, not V1/V2 two-byte UNWIND_CODE slots.
// https://learn.microsoft.com/en-us/cpp/build/x64-unwind-information-v3#winding-operation-descriptors-wods
// https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/lib/Support/Win64EH.cpp
const readOperand = (pool: DataView, offset: number, byteLength: number): number | null => {
  if (offset + byteLength > pool.byteLength) return null;
  if (byteLength === 2) return pool.getUint8(offset + 1);
  return byteLength === 3 ? pool.getUint16(offset + 1, true) : pool.getUint32(offset + 1, true);
};

const readShortPrefix = (pool: DataView, offset: number, first: number): DecodedWinding | null => {
  const opcode = first & 7;
  const register = first >>> 3;
  if (opcode === 4) return { operation: { opcode: "PUSH", register }, byteLength: 1 };
  if (opcode === 7) return register > 30 ? null :
    { operation: { opcode: "PUSH_CONSECUTIVE_2", register }, byteLength: 1 };
  const byteLength = opcode === 5 ? 5 : 3;
  const operand = readOperand(pool, offset, byteLength);
  if (operand == null) return null;
  return { operation: { opcode: opcode === 5 ? "SAVE_NONVOL_FAR" : "SAVE_NONVOL",
    register, displacement: operand * (opcode === 5 ? 1 : 8) }, byteLength };
};

const readFourBitPrefix = (pool: DataView, offset: number, first: number): DecodedWinding | null => {
  const opcode = first & 15;
  if (opcode === 8) return { operation: { opcode: "ALLOC_SMALL", size: ((first >>> 4) + 1) * 8 }, byteLength: 1 };
  if (opcode !== 9 && opcode !== 10) return null;
  const byteLength = opcode === 9 ? 5 : 3;
  const operand = readOperand(pool, offset, byteLength);
  if (operand == null) return null;
  return { operation: { opcode: opcode === 9 ? "SAVE_XMM128_FAR" : "SAVE_XMM128",
    register: first >>> 4, displacement: operand * (opcode === 9 ? 1 : 16) }, byteLength };
};

const readLongPrefix = (pool: DataView, offset: number, first: number): DecodedWinding | null => {
  if ((first & 63) === 32) {
    const operand = readOperand(pool, offset, 2);
    return operand == null ? null : { operation: { opcode: "PUSH2",
      register: (first >>> 6) | ((operand & 7) << 2), register2: operand >>> 3 }, byteLength: 2 };
  }
  if (first > 3) return null;
  const byteLength = [2, 5, 3, 2][first]!;
  const operand = readOperand(pool, offset, byteLength);
  if (operand == null) return null;
  if (first === 0) return { operation: { opcode: "SET_FPREG", register: operand & 15,
    displacement: (operand >>> 4) * 16 }, byteLength };
  if (first === 3) return { operation: { opcode: "PUSH_CANONICAL_FRAME", frameType: operand }, byteLength };
  return { operation: { opcode: first === 1 ? "ALLOC_HUGE" : "ALLOC_LARGE",
    size: operand * (first === 1 ? 1 : 8) }, byteLength };
};

const decodeWinding = (pool: DataView, offset: number): DecodedWinding | null => {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= pool.byteLength) return null;
  const first = pool.getUint8(offset);
  if ((first & 7) >= 4) return readShortPrefix(pool, offset, first);
  if ((first & 15) >= 8) return readFourBitPrefix(pool, offset, first);
  return readLongPrefix(pool, offset, first);
};

/** Pool-local cache, including failures, shared by prolog and all epilog references. */
export const createV3WindingReader = (pool: DataView) => {
  const cache = new Map<number, DecodedWinding | null>();
  const operands = new Set<number>();
  const read = (offset: number): DecodedWinding | null => {
    if (operands.has(offset)) return null;
    const decoded = decodeWinding(pool, offset);
    if (!decoded) return null;
    for (let byte = offset + 1; byte < offset + decoded.byteLength; byte++) {
      if (cache.get(byte)) return null;
    }
    for (let byte = offset + 1; byte < offset + decoded.byteLength; byte++) operands.add(byte);
    return decoded;
  };
  return (firstOp: number, count: number, issues: string[]): Amd64WindingOperation[] => {
    const operations: Amd64WindingOperation[] = [];
    if (!Number.isSafeInteger(count) || count < 0 || count > 31) {
      issues.push("UNWIND_INFO v3 has an invalid winding-operation count.");
      return operations;
    }
    let offset = firstOp;
    for (let index = 0; index < count; index++) {
      if (!cache.has(offset)) cache.set(offset, read(offset));
      const decoded = cache.get(offset);
      if (!decoded) {
        issues.push(`UNWIND_INFO v3 has an invalid or truncated WOD at pool byte ${offset}.`);
        break;
      }
      operations.push(decoded.operation);
      offset += decoded.byteLength;
    }
    return operations;
  };
};
