"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import type { PeBaseRelocationResult } from "./directories/reloc.js";
import {
  MAX_NATIVE_AOT_SECTIONS,
  NATIVE_AOT_EMBEDDED_METADATA_SECTION,
  NATIVE_AOT_HEADER_SIZE,
  NATIVE_AOT_METADATA_SIGNATURE,
  NATIVE_AOT_READY_TO_RUN_SIGNATURE,
  isSupportedNativeAotSectionType,
  type PeNativeAotMetadata,
  type PeNativeAotMetadataLayout,
  type PeNativeAotMetadataSection
} from "./native-aot/format.js";
import {
  createNativeAotImage,
  getNativeAotArchitecture,
  indexNativeAotPointerSites,
  readNativeAotPointerRva,
  type NativeAotImage
} from "./native-aot/image.js";
import {
  MAX_NATIVE_AOT_REFLECTION_METADATA_BYTES,
  parseNativeAotReflectionMetadata
} from "./native-aot/reflection-metadata.js";
import type { PeWindowsCore } from "./types.js";

interface ParsedHeader {
  layout: PeNativeAotMetadataLayout;
  headerRva: number;
  majorVersion: number;
  minorVersion: number;
  sections: PeNativeAotMetadataSection[];
  reflection: NonNullable<PeNativeAotMetadata["reflection"]>;
}

const parsePointerRangeEntry = async (
  image: NativeAotImage,
  sites: Set<number>,
  view: DataView,
  entryRva: number
): Promise<{ rva: number; size: number | null } | null> => {
  const flags = view.getUint32(4, true);
  const startSlotRva = entryRva + 8;
  const endSlotRva = startSlotRva + image.pointerSize;
  if ((flags !== 0 && flags !== 1) || !sites.has(startSlotRva)) return null;
  const rva = await readNativeAotPointerRva(image, startSlotRva);
  if (rva == null) return null;
  if (flags === 0) {
    const endValue = await image.readPointerValue(endSlotRva);
    return !sites.has(endSlotRva) && endValue === 0n && image.isMappedRange(rva, 1)
      ? { rva, size: null }
      : null;
  }
  if (!sites.has(endSlotRva)) return null;
  const endRva = await readNativeAotPointerRva(image, endSlotRva);
  if (endRva == null || endRva < rva) return null;
  if (endRva === rva) return image.isMappedRange(rva, 1) ? { rva, size: 0 } : null;
  return image.isMappedRange(rva, endRva - rva) ? { rva, size: endRva - rva } : null;
};

const parseSizePointerEntry = async (
  image: NativeAotImage,
  sites: Set<number>,
  view: DataView,
  entryRva: number
): Promise<{ rva: number; size: number } | null> => {
  const size = view.getUint32(4, true);
  const pointerSlotRva = entryRva + 8;
  if (!sites.has(pointerSlotRva)) return null;
  const rva = await readNativeAotPointerRva(image, pointerSlotRva);
  if (rva == null) return null;
  const mapped = size === 0 ? image.isMappedRange(rva, 1) : image.isMappedRange(rva, size);
  return mapped ? { rva, size } : null;
};

const parseHeaderSections = async (
  image: NativeAotImage,
  sites: Set<number>,
  headerRva: number,
  count: number,
  entrySize: number,
  layout: PeNativeAotMetadataLayout
): Promise<PeNativeAotMetadataSection[] | null> => {
  const tableRva = headerRva + NATIVE_AOT_HEADER_SIZE;
  const table = await image.readData(tableRva, count * entrySize, 4);
  if (!table) return null;
  const sections: PeNativeAotMetadataSection[] = [];
  let previousType = 0;
  for (let index = 0; index < count; index += 1) {
    const offset = index * entrySize;
    const type = table.getUint32(offset, true);
    if (!isSupportedNativeAotSectionType(type) || type <= previousType) return null;
    const entryView = new DataView(table.buffer, table.byteOffset + offset, entrySize);
    const range = layout === "nativeaot-readytorun-pointer-range-v1"
      ? await parsePointerRangeEntry(image, sites, entryView, tableRva + offset)
      : await parseSizePointerEntry(image, sites, entryView, tableRva + offset);
    if (!range) return null;
    sections.push({ type, ...range });
    previousType = type;
  }
  return sections;
};

const layoutForEntrySize = (
  entrySize: number,
  pointerSize: 4 | 8
): PeNativeAotMetadataLayout | null => {
  if (entrySize === 8 + pointerSize * 2) return "nativeaot-readytorun-pointer-range-v1";
  if (entrySize === 8 + pointerSize) return "nativeaot-readytorun-size-pointer-v1";
  return null;
};

const hasValidEmbeddedMetadata = async (
  image: NativeAotImage,
  sections: PeNativeAotMetadataSection[]
): Promise<boolean> => {
  const metadata = sections.find(section => section.type === NATIVE_AOT_EMBEDDED_METADATA_SECTION);
  if (metadata?.size == null || metadata.size < 4) return false;
  if (!image.isDataRange(metadata.rva, metadata.size, 4)) return false;
  const view = await image.readData(metadata.rva, 4, 4);
  return view?.getUint32(0, true) === NATIVE_AOT_METADATA_SIGNATURE;
};

const parseEmbeddedReflectionMetadata = async (
  image: NativeAotImage,
  sections: PeNativeAotMetadataSection[]
): Promise<NonNullable<PeNativeAotMetadata["reflection"]>> => {
  const metadata = sections.find(section => section.type === NATIVE_AOT_EMBEDDED_METADATA_SECTION);
  if (metadata?.size == null || metadata.size > MAX_NATIVE_AOT_REFLECTION_METADATA_BYTES) {
    return {
      scopes: [],
      warnings: ["NativeFormat metadata exceeds its 32 MiB handle range."]
    };
  }
  try {
    const view = await image.readData(metadata.rva, metadata.size, 4);
    if (!view) return { scopes: [], warnings: ["NativeFormat metadata could not be read."] };
    return parseNativeAotReflectionMetadata(
      new Uint8Array(view.buffer, view.byteOffset, view.byteLength)
    );
  } catch {
    return { scopes: [], warnings: ["NativeFormat metadata could not be read."] };
  }
};

const parseNativeAotHeader = async (
  image: NativeAotImage,
  sites: Set<number>,
  headerRva: number
): Promise<ParsedHeader | null> => {
  const header = await image.readData(headerRva, NATIVE_AOT_HEADER_SIZE, image.pointerSize);
  if (!header || header.getUint32(0, true) !== NATIVE_AOT_READY_TO_RUN_SIGNATURE) return null;
  const flags = header.getUint32(8, true);
  const count = header.getUint16(12, true);
  const entrySize = header.getUint8(14);
  const entryType = header.getUint8(15);
  const layout = layoutForEntrySize(entrySize, image.pointerSize);
  if (!header.getUint16(4, true) || flags !== 0 || !count ||
    count > MAX_NATIVE_AOT_SECTIONS || entryType !== 1 || !layout) {
    return null;
  }
  const sections = await parseHeaderSections(image, sites, headerRva, count, entrySize, layout);
  if (!sections?.some(section => section.type >= 201 && section.type <= 215)) return null;
  if (!await hasValidEmbeddedMetadata(image, sections)) return null;
  return {
    layout,
    headerRva,
    majorVersion: header.getUint16(4, true),
    minorVersion: header.getUint16(6, true),
    sections,
    reflection: await parseEmbeddedReflectionMetadata(image, sections)
  };
};

export const analyzePeNativeAotMetadata = async (
  reader: FileRangeReader,
  core: PeWindowsCore,
  relocations: PeBaseRelocationResult | null
): Promise<PeNativeAotMetadata | null> => {
  const architecture = getNativeAotArchitecture(core);
  if (!architecture) return null;
  try {
    const image = createNativeAotImage(
      reader,
      core,
      architecture.pointerSize,
      architecture.relocationType
    );
    const sites = indexNativeAotPointerSites(relocations, image);
    if (!sites) return null;
    const checkedHeaders = new Set<number>();
    for (const modulePointerRva of sites) {
      const headerRva = await readNativeAotPointerRva(image, modulePointerRva);
      if (headerRva == null || checkedHeaders.has(headerRva)) continue;
      checkedHeaders.add(headerRva);
      const header = await parseNativeAotHeader(image, sites, headerRva);
      if (header) return { status: "confirmed", modulePointerRva, ...header };
    }
  } catch {
    // A relocation site is only a candidate; malformed/truncated candidates are expected.
  }
  return null;
};
