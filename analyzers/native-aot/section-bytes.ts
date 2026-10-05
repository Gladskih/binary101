import type { NativeAotMetadataSection } from "./format.js";
import type { NativeAotVirtualImage } from "./virtual-image-types.js";

const isSectionSize = (size: number | null): size is number =>
  size !== null && Number.isSafeInteger(size) && size >= 0;

const readablePrefix = (
  image: NativeAotVirtualImage, rva: number, size: number
): number => {
  let lower = 0;
  let upper = size;
  while (lower < upper) {
    const middle = lower + Math.ceil((upper - lower) / 2);
    if (image.isDataRange(rva, middle, 1)) lower = middle;
    else upper = middle - 1;
  }
  return lower;
};

export const readNativeAotSectionBytes = async (
  image: NativeAotVirtualImage, section: NativeAotMetadataSection, issues: Set<string>
): Promise<Uint8Array> => {
  if (!isSectionSize(section.size)) {
    issues.add("Section has an unknown or invalid size.");
    return new Uint8Array();
  }
  try {
    const length = readablePrefix(image, section.rva, section.size);
    if (length < section.size) issues.add("Section is truncated or not fully file-backed.");
    if (!length) return new Uint8Array();
    const view = await image.readData(section.rva, length, 1);
    if (!view) { issues.add("Section could not be read."); return new Uint8Array(); }
    if (view.byteLength < length) issues.add("Section read returned a truncated prefix.");
    return new Uint8Array(view.buffer, view.byteOffset, Math.min(view.byteLength, length));
  } catch (error) {
    issues.add(error instanceof Error ? error.message : "Section read failed.");
    return new Uint8Array();
  }
};
