"use strict";

import type { NativeAotVirtualImage } from "./virtual-image-types.js";
import { parseNativeAotInitializers } from "./initializers.js";
import { parseNativeAotInvokeMap } from "./invoke-map.js";
import { parseNativeAotStackTraceMap } from "./stack-trace-map.js";
import { parseNativeAotFunctionMaps } from "./function-maps.js";
import {
  NATIVE_AOT_EMBEDDED_METADATA_SECTION,
  NATIVE_AOT_HEADER_SIZE,
  NATIVE_AOT_METADATA_SIGNATURE,
  NATIVE_AOT_READY_TO_RUN_SIGNATURE,
  isSupportedNativeAotSectionType,
  type NativeAotMetadata,
  type NativeAotMetadataLayout,
  type NativeAotMetadataSection,
  type NativeAotReflectionMetadata
} from "./format.js";
import {
  parseNativeAotReflectionMetadata
} from "./reflection-metadata.js";

export interface NativeAotReadyToRunHeader {
  layout: NativeAotMetadataLayout;
  headerRva: number;
  majorVersion: number;
  minorVersion: number;
  sections: NativeAotMetadataSection[];
  reflection?: NativeAotReflectionMetadata;
}

const parseClosedPointerRange = async (
  image: NativeAotVirtualImage, sites: ReadonlySet<number>, endSlotRva: number, rva: number
): Promise<{ rva: number; size: number } | null> => {
  if (!sites.has(endSlotRva)) return null;
  const endRva = await image.readPointerTarget(endSlotRva);
  if (endRva == null || endRva < rva) return null;
  const size = endRva - rva;
  return image.isMappedRange(rva, size || 1) ? { rva, size } : null;
};

const parseOpenPointerRange = async (
  image: NativeAotVirtualImage, sites: ReadonlySet<number>, endSlotRva: number, rva: number
): Promise<{ rva: number; size: null } | null> => {
  const endValue = await image.readPointerValue(endSlotRva);
  return !sites.has(endSlotRva) && endValue === 0n && image.isMappedRange(rva, 1)
    ? { rva, size: null } : null;
};

const parsePointerRangeEntry = async (
  image: NativeAotVirtualImage,
  sites: ReadonlySet<number>,
  view: DataView,
  entryRva: number
): Promise<{ rva: number; size: number | null } | null> => {
  const flags = view.getUint32(4, true);
  const startSlotRva = entryRva + 8;
  const endSlotRva = startSlotRva + image.pointerSize;
  if ((flags !== 0 && flags !== 1) || !sites.has(startSlotRva)) return null;
  const rva = await image.readPointerTarget(startSlotRva);
  if (rva == null) return null;
  return flags === 0 ? parseOpenPointerRange(image, sites, endSlotRva, rva)
    : parseClosedPointerRange(image, sites, endSlotRva, rva);
};

const parseSizePointerEntry = async (
  image: NativeAotVirtualImage,
  sites: ReadonlySet<number>,
  view: DataView,
  entryRva: number
): Promise<{ rva: number; size: number } | null> => {
  const size = view.getUint32(4, true);
  const pointerSlotRva = entryRva + 8;
  if (!sites.has(pointerSlotRva)) return null;
  const rva = await image.readPointerTarget(pointerSlotRva);
  if (rva == null) return null;
  const mapped = size === 0 ? image.isMappedRange(rva, 1) : image.isMappedRange(rva, size);
  return mapped ? { rva, size } : null;
};

const parseHeaderSections = async (
  image: NativeAotVirtualImage,
  sites: ReadonlySet<number>,
  headerRva: number,
  count: number,
  entrySize: number,
  layout: NativeAotMetadataLayout
): Promise<NativeAotMetadataSection[] | null> => {
  const tableRva = headerRva + NATIVE_AOT_HEADER_SIZE;
  const table = await image.readData(tableRva, count * entrySize, 4);
  if (!table || table.byteLength < count * entrySize) return null;
  const sections: NativeAotMetadataSection[] = [];
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
): NativeAotMetadataLayout | null => {
  if (entrySize === 8 + pointerSize * 2) return "nativeaot-readytorun-pointer-range-v1";
  if (entrySize === 8 + pointerSize) return "nativeaot-readytorun-size-pointer-v1";
  return null;
};

const findEmbeddedMetadata = (
  sections: NativeAotMetadataSection[]
): NativeAotMetadataSection | undefined =>
  sections.find(section => section.type === NATIVE_AOT_EMBEDDED_METADATA_SECTION);

const findValidatedEmbeddedMetadata = async (
  image: NativeAotVirtualImage,
  sections: NativeAotMetadataSection[]
): Promise<(NativeAotMetadataSection & { size: number }) | null> => {
  const metadata = findEmbeddedMetadata(sections);
  if (metadata?.size == null || metadata.size < 4) return null;
  if (!image.isDataRange(metadata.rva, metadata.size, 4)) return null;
  const view = await image.readData(metadata.rva, 4, 4);
  return view != null && view.byteLength >= 4 &&
    view.getUint32(0, true) === NATIVE_AOT_METADATA_SIGNATURE
    ? metadata as NativeAotMetadataSection & { size: number } : null;
};

const parseEmbeddedReflectionMetadata = async (
  image: NativeAotVirtualImage,
  metadata: NativeAotMetadataSection & { size: number }
): Promise<NativeAotReflectionMetadata> => {
  try {
    const view = await image.readData(metadata.rva, metadata.size, 4);
    if (!view) return { scopes: [], warnings: ["NativeFormat metadata could not be read."] };
    const reflection = parseNativeAotReflectionMetadata(
      new Uint8Array(view.buffer, view.byteOffset, view.byteLength)
    );
    if (view.byteLength < metadata.size) {
      reflection.warnings = [...reflection.warnings ?? [], "NativeFormat metadata is truncated."];
    }
    return reflection;
  } catch {
    return { scopes: [], warnings: ["NativeFormat metadata could not be read."] };
  }
};

const isKnownHeaderEncoding = (header: DataView): boolean =>
  header.getUint16(4, true) !== 0 && header.getUint32(8, true) === 0 &&
  header.getUint16(12, true) !== 0 && header.getUint8(15) === 1;

const hasNativeRuntimeSections = (sections: NativeAotMetadataSection[] | null):
  sections is NativeAotMetadataSection[] =>
  sections !== null && sections.some(section => section.type >= 201 && section.type <= 215);

const isInvalidEmbeddedMetadata = (metadata: NativeAotMetadataSection | null,
  sections: NativeAotMetadataSection[]): boolean => !metadata && findEmbeddedMetadata(sections) !== undefined;

export const parseNativeAotReadyToRunHeader = async (
  image: NativeAotVirtualImage,
  sites: ReadonlySet<number>,
  headerRva: number
): Promise<NativeAotReadyToRunHeader | null> => {
  const header = await image.readData(headerRva, NATIVE_AOT_HEADER_SIZE, image.pointerSize);
  if (!header || header.byteLength < NATIVE_AOT_HEADER_SIZE ||
    header.getUint32(0, true) !== NATIVE_AOT_READY_TO_RUN_SIGNATURE) return null;
  const count = header.getUint16(12, true);
  const entrySize = header.getUint8(14);
  const layout = layoutForEntrySize(entrySize, image.pointerSize);
  if (!isKnownHeaderEncoding(header) || !layout) return null;
  const sections = await parseHeaderSections(image, sites, headerRva, count, entrySize, layout);
  if (!hasNativeRuntimeSections(sections)) return null;
  const metadata = await findValidatedEmbeddedMetadata(image, sections);
  // Reflection metadata is optional; the validated runtime header and pointer ranges
  // establish NativeAOT even when compilation omits reflection support.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Runtime/inc/ModuleHeaders.h
  if (isInvalidEmbeddedMetadata(metadata, sections)) return null;
  return {
    layout,
    headerRva,
    majorVersion: header.getUint16(4, true),
    minorVersion: header.getUint16(6, true),
    sections,
    ...(metadata ? { reflection: await parseEmbeddedReflectionMetadata(image, metadata) } : {})
  };
};

export const findNativeAotMetadata = async (
  image: NativeAotVirtualImage,
  sites: ReadonlySet<number>
): Promise<NativeAotMetadata | null> => {
  const checkedHeaders = new Set<number>();
  for (const modulePointerRva of sites) {
    const headerRva = await image.readPointerTarget(modulePointerRva);
    if (headerRva == null || checkedHeaders.has(headerRva)) continue;
    checkedHeaders.add(headerRva);
    const header = await parseNativeAotReadyToRunHeader(image, sites, headerRva);
    if (header) {
      const invokeMap = await parseNativeAotInvokeMap(image, header.sections);
      const stackTraceMap = await parseNativeAotStackTraceMap(image, header.sections);
      const functionMaps = await parseNativeAotFunctionMaps(image, header.sections, header);
      return { status: "confirmed", modulePointerRva, ...header,
        initializers: await parseNativeAotInitializers(image, header),
        ...(invokeMap ? { invokeMap } : {}), ...(stackTraceMap ? { stackTraceMap } : {}),
        ...(functionMaps ? { functionMaps } : {}) };
    }
  }
  return null;
};
