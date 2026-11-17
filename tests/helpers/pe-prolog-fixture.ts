import type { Amd64PrologDescription } from "../../analyzers/pe/exception/amd64/prolog-types.js";
import { MockFile } from "./mock-file.js";

export const prologDescription = (operations: Amd64PrologDescription["operations"], prologSize: number,
  fields: Partial<Amd64PrologDescription> = {}): Amd64PrologDescription => ({
  version: 1, flags: 0, prologSize, frameRegister: 0, frameOffset: 0,
  operations, complete: true, ...fields
});

export const prologCodeImage = (code: number[], copies = 1) => {
  const bytes = new Uint8Array((code.length + 16) * copies);
  const ranges = Array.from({ length: copies }, (_, index) => {
    const begin = 16 + index * (code.length + 16);
    bytes.set(code, begin);
    return { begin, end: begin + code.length, sourceUnwindInfoRva: 1 };
  });
  return { bytes, file: new MockFile(bytes), owners: new Map([[1, ranges]]) };
};

export const distinctConstantPrologs = (count: number) => {
  const bytes = new Uint8Array(16 + count * 6);
  const view = new DataView(bytes.buffer);
  const ranges = Array.from({ length: count }, (_, index) => {
    const begin = 16 + index * 6;
    bytes[begin] = 0xb8; // MOV EAX, imm32: five-byte prolog, followed by body NOP.
    view.setUint32(begin + 1, index, true);
    bytes[begin + 5] = 0x90;
    return { begin, end: begin + 6, sourceUnwindInfoRva: 1 };
  });
  return { bytes, file: new MockFile(bytes), owners: new Map([[1, ranges]]) };
};

export const feedPrologDescriptions = async (
  observe: (rva: number, description: Amd64PrologDescription) => Promise<void>,
  rvas: Iterable<number>, description: Amd64PrologDescription
): Promise<void> => {
  for (const rva of rvas) await observe(rva, description);
};
