import type { FileRangeReader } from "../file-range-reader.js";
import type { ItaniumRttiImage } from "../itanium-rtti/types.js";
import type { PeWindowsCore } from "./types.js";

const overlaps = (ranges: Array<{ start: number; length: number }>): boolean => {
  const ordered = ranges.filter(range => range.length > 0)
    .sort((left, right) => left.start - right.start);
  return ordered.some((range, index) => index > 0 &&
    range.start < ordered[index - 1]!.start + ordered[index - 1]!.length);
};

export const createPeItaniumImage = (
  reader: FileRangeReader, core: PeWindowsCore, pointerSize: 4 | 8
): ItaniumRttiImage | null => {
  const { ImageBase, SizeOfImage } = core.opt;
  if (ImageBase < 0n || !Number.isSafeInteger(SizeOfImage) || SizeOfImage <= 0) return null;
  const sections = core.sections.map(section => ({
    start: section.virtualAddress,
    length: Math.min(section.virtualSize || section.sizeOfRawData, section.sizeOfRawData),
    offset: section.pointerToRawData,
    characteristics: section.characteristics
  }));
  if (sections.some(section => [section.start, section.length, section.offset]
    .some(value => !Number.isSafeInteger(value) || value < 0))) return null;
  if (sections.some(section =>
    section.start + section.length > Math.min(SizeOfImage, 0x1_0000_0000))) return null;
  if (overlaps(sections) || overlaps(sections.map(section => ({
    start: section.offset, length: section.length
  })))) return null;
  const locate = (address: number) => Number.isSafeInteger(address) && address >= 0
    ? sections.find(section => address >= section.start && address < section.start + section.length)
    : undefined;
  return {
    pointerSize,
    pointers: new Map(),
    relocations: new Set(),
    readOrder: address => {
      const section = locate(address);
      return section ? section.offset + address - section.start : Infinity;
    },
    read: async (address, size) => {
      const section = locate(address);
      // PE/COFF section flags: initialized readable data, never executable.
      // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
      if (!section || (section.characteristics & 0x60000040) !== 0x40000040 ||
          !Number.isSafeInteger(size) || size <= 0) return new DataView(new ArrayBuffer(0));
      const offset = section.offset + address - section.start;
      if (offset >= reader.size) return new DataView(new ArrayBuffer(0));
      return reader.read(offset, Math.min(size, section.start + section.length - address,
        reader.size - offset));
    },
    isExecutable: address => {
      const section = locate(address);
      return section != null && (section.characteristics & 0x20000000) !== 0 &&
        section.offset + address - section.start < reader.size;
    }
  };
};
