import type { ResourceSection } from "./types.js";
import { validResourceRange } from "./reader.js";

export interface ResourceSignature { offset: number; end: number; kind: "rcc" | "gresource" }

const matches = (bytes: Uint8Array, index: number, signature: string): boolean => {
  for (let cursor = 0; cursor < signature.length; cursor += 1) {
    if (bytes[index + cursor] !== signature.charCodeAt(cursor)) return false;
  }
  return true;
};

const signatureKind = (bytes: Uint8Array, index: number): ResourceSignature["kind"] | null => {
  if (bytes[index] === 0x71 && matches(bytes, index + 1, "res")) return "rcc";
  if (bytes[index] === 0x47 && matches(bytes, index + 1, "Variant")) return "gresource";
  if (bytes[index] === 0x72 && matches(bytes, index + 1, "aVGtnai")) return "gresource";
  return null;
};

// Scan each physical byte once even for aliased or overlapping executable sections.
const scanRanges = (sections: ResourceSection[], fileSize: number): ResourceSection[] => {
  const sorted = sections.filter(section => section.size > 0 &&
    validResourceRange(section.offset, section.size, fileSize)).sort((left, right) => left.offset - right.offset);
  const ranges: ResourceSection[] = [];
  for (const section of sorted) {
    const previous = ranges.at(-1);
    if (previous && section.offset < previous.offset + previous.size) {
      previous.size = Math.max(previous.size, section.offset + section.size - previous.offset);
    } else ranges.push({ ...section });
  }
  return ranges;
};

export async function* findResourceSignatures(file: File,
  sections: ResourceSection[]): AsyncGenerator<ResourceSignature> {
  for (const range of scanRanges(sections, file.size)) {
    const reader = file.slice(range.offset, range.offset + range.size).stream().getReader();
    let carry = new Uint8Array(0);
    let offset = range.offset;
    try {
      while (true) {
        const next = await reader.read();
        const chunk = next.value ?? new Uint8Array();
        const bytes = new Uint8Array(carry.length + chunk.length);
        bytes.set(carry);
        bytes.set(chunk, carry.length);
        const base = offset - carry.length;
        const limit = next.done ? bytes.length : bytes.length - 7;
        for (let index = 0; index < limit; index += 1) {
          const kind = signatureKind(bytes, index);
          if (kind) yield { offset: base + index, end: range.offset + range.size, kind };
        }
        if (next.done) break;
        carry = bytes.slice(-7);
        offset += chunk.length;
      }
    } finally {
      reader.releaseLock();
    }
  }
}
