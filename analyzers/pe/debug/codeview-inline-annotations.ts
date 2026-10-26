import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import type { CodeViewInlineAnnotation } from "./codeview-scope-types.js";

// Microsoft cvinfo.h Compress/UncompressAnnotation and BinaryAnnotationOpcode.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L4839
const compressed = (bytes: Uint8Array, offset: number): { value: number; end: number } => {
  const first = bytes[offset];
  if (first === undefined || first >= 0xe0) throw new Error("Invalid or truncated compressed integer.");
  const size = first < 0x80 ? 1 : first < 0xc0 ? 2 : 4;
  if (size > bytes.length - offset) throw new Error("Truncated compressed integer.");
  let value = first & (size === 1 ? 0x7f : size === 2 ? 0x3f : 0x1f);
  for (let index = 1; index < size; index++) value = value * 256 + bytes[offset + index]!;
  return { value, end: offset + size };
};

const signed = (value: number): number => value & 1 ? -(value >>> 1) : value >>> 1;
const decodeOperands = (opcode: number, operands: number[]): number[] => {
  if (opcode === 6 || opcode === 10) return [signed(operands[0]!)];
  if (opcode === 11) return [operands[0]! & 15, signed(operands[0]! >>> 4)];
  return operands;
};

const instruction = (bytes: Uint8Array, start: number): { annotation: CodeViewInlineAnnotation; end: number } => {
  const opcode = compressed(bytes, start);
  if (opcode.value < 1 || opcode.value > 13) throw new Error(`Unknown inline annotation opcode ${opcode.value}.`);
  const operands: number[] = [];
  let end = opcode.end;
  for (let index = 0; index < (opcode.value === 12 ? 2 : 1); index++) {
    const operand = compressed(bytes, end);
    operands.push(operand.value);
    end = operand.end;
  }
  return { annotation: { opcode: opcode.value, operands: decodeOperands(opcode.value, operands) }, end };
};

export const readCodeViewInlineAnnotations = async (reader: LegacyCodeViewReader,
  start: number): Promise<CodeViewInlineAnnotation[]> => {
  const result: CodeViewInlineAnnotation[] = [];
  try {
    const view = await reader.view(start, reader.size - start);
    const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    for (let offset = 0; offset < bytes.length;) {
      if (bytes[offset] === 0) {
        if (bytes.subarray(offset).some(value => value !== 0)) reader.warn("Inline annotation padding contains nonzero bytes.");
        break;
      }
      const value = instruction(bytes, offset);
      result.push(value.annotation);
      offset = value.end;
    }
  } catch (error) { reader.warn(`CodeView inline annotations: ${String(error)}`); }
  return result;
};
