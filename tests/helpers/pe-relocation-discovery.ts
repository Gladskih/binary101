import assert from "node:assert/strict";
import { createPeRelocationDiscovery } from "../../analyzers/pe/relocation-discovery-state.js";
import { createNativeAotMetadataFixture } from "./pe-native-aot-metadata-fixture.js";
import { createSimpleMsvcRttiFixture } from "../fixtures/pe-msvc-rtti-fixture.js";
import { createMemoryRangeReader } from "../../analyzers/memory-range-reader.js";
import type { NativeAotMetadataFixture } from "./pe-native-aot-metadata-fixture.js";
import {
  createMsvcRttiFixtureSections, writeMsvcRttiFixtureHeaders, writeMsvcRttiFixtureRelocations
} from "../fixtures/pe-msvc-rtti-pe.js";
import { MockFile } from "./mock-file.js";
import { createPeItaniumFixture } from "../fixtures/pe-itanium-rtti.js";
import { isPeWindowsCore, parsePeHeaders } from "../../analyzers/pe/core/index.js";
import { inlinePeSectionName } from "../../analyzers/pe/sections/name.js";

export const nativeDiscovery = (width: 4 | 8 = 8) => {
  const fixture = createNativeAotMetadataFixture(width);
  const reader = createMemoryRangeReader(fixture.bytes);
  const state = createPeRelocationDiscovery(reader, fixture.core, fixture.relocations);
  assert.ok(state);
  return { fixture, reader, state };
};

export const msvcDiscovery = () => {
  const source = createSimpleMsvcRttiFixture(2);
  const fixture = source.builder.build();
  const reader = createMemoryRangeReader(fixture.bytes);
  const state = createPeRelocationDiscovery(reader, fixture.core, fixture.relocations);
  assert.ok(state);
  return { ...source, fixture, reader, state };
};

export const addNativeSites = (fixture: NativeAotMetadataFixture, sites: number[]): void => {
  const block = fixture.relocations.blocks[0]!;
  const entries = block.entries.filter(entry => entry.type !== 0);
  entries.push(...sites.map(rva => ({ type: fixture.pointerSize === 8 ? 10 : 3,
    offset: rva - block.pageRva })));
  if (entries.length % 2) entries.push({ type: 0, offset: 0 });
  block.entries = entries;
  block.count = entries.length;
  block.size = 8 + 2 * entries.length;
  fixture.relocations.totalEntries = entries.length;
};

export const twoNativeHeaders = () => {
  const fixture = createNativeAotMetadataFixture();
  // Independent PE layout: module pointer 0x1060 precedes 0x1080, but its
  // target header 0x1500 follows 0x1100. Header size is 16 + two 24-byte entries.
  fixture.bytes.copyWithin(0x500, 0x100, 0x140);
  fixture.view.setBigUint64(0x60, fixture.core.opt.ImageBase + 0x1500n, true);
  addNativeSites(fixture, [0x1060, 0x1518, 0x1520, 0x1530, 0x1538]);
  const entries = fixture.relocations.blocks[0]!.entries;
  entries.unshift(...entries.splice(entries.findIndex(entry => entry.offset === 0x60), 1));
  const reader = createMemoryRangeReader(fixture.bytes);
  const state = createPeRelocationDiscovery(reader, fixture.core, fixture.relocations);
  assert.ok(state);
  return { fixture, reader, state };
};

const addSparsePointer = (fixture: NativeAotMetadataFixture, offset: number): void => {
  const pageRva = 0x1000 + offset - offset % 4096;
  const block = fixture.relocations.blocks.find(block => block.pageRva === pageRva);
  const entries = [...(block?.entries.filter(entry => entry.type !== 0) ?? []),
    { type: 10, offset: offset % 4096 }];
  if (entries.length % 2) entries.push({ type: 0, offset: 0 });
  fixture.relocations.totalEntries += entries.length - (block?.entries.length ?? 0);
  if (block) Object.assign(block, { size: 8 + 2 * entries.length, count: entries.length, entries });
  else fixture.relocations.blocks.unshift({ pageRva, size: 8 + 2 * entries.length, count: entries.length, entries });
  fixture.view.setBigUint64(offset, fixture.core.opt.ImageBase + BigInt(fixture.headerRva), true);
};

export const sparseNativeDiscovery = (additionalOffsets: number[] = []) => {
  const fixture = createNativeAotMetadataFixture();
  const bytes = new Uint8Array(0x22000);
  bytes.set(fixture.bytes);
  fixture.bytes = bytes;
  fixture.view = new DataView(bytes.buffer);
  fixture.core.sections[0]!.virtualSize = bytes.length;
  fixture.core.sections[0]!.sizeOfRawData = bytes.length;
  fixture.core.opt.SizeOfImage = 0x24000;
  fixture.core.rvaToOff = rva => rva >= 0x1000 && rva < 0x23000 ? rva - 0x1000 : null;
  // Three relocated pointers, one per distant 64-KiB window, deliberately reversed.
  for (const offset of [0x20080, 0x10080, ...additionalOffsets]) addSparsePointer(fixture, offset);
  fixture.relocations.blocks.reverse();
  const reader = createMemoryRangeReader(bytes);
  const state = createPeRelocationDiscovery(reader, fixture.core, fixture.relocations);
  assert.ok(state);
  return { fixture, reader, state };
};

export const boundaryMsvcDiscovery = () => {
  const { fixture, vftable } = msvcDiscovery();
  const section = fixture.core.sections[1]!;
  const delta = vftable.rva - section.virtualAddress;
  fixture.core.sections.splice(1, 1,
    { ...section, virtualSize: delta, sizeOfRawData: delta },
    { ...section, virtualAddress: vftable.rva, pointerToRawData: section.pointerToRawData + delta,
      virtualSize: section.virtualSize - delta, sizeOfRawData: section.sizeOfRawData - delta });
  const reader = createMemoryRangeReader(fixture.bytes);
  const state = createPeRelocationDiscovery(reader, fixture.core, fixture.relocations);
  assert.ok(state);
  return { fixture, reader, state, vftable };
};

export const crossedMsvcDiscovery = () => {
  const source = createSimpleMsvcRttiFixture();
  const second = source.builder.addVftable(source.hierarchy, [source.builder.allocateFunctionTarget()]);
  const values = [source.builder.view.getBigUint64(source.builder.offsetOf(source.vftable.locatorSlotRva), true),
    source.builder.view.getBigUint64(source.builder.offsetOf(second.locatorSlotRva), true)];
  source.builder.patchBigUint64(source.vftable.locatorSlotRva, values[1]!);
  source.builder.patchBigUint64(second.locatorSlotRva, values[0]!);
  const fixture = source.builder.build();
  const state = createPeRelocationDiscovery(createMemoryRangeReader(fixture.bytes), fixture.core, fixture.relocations);
  assert.ok(state);
  return { first: source.vftable, second, state };
};

export const nativeDiscoveryPeFile = (): MockFile => {
  const fixture = createNativeAotMetadataFixture();
  const bytes = new Uint8Array(0x2800);
  const view = new DataView(bytes.buffer);
  bytes.set(fixture.bytes, 0x400);
  const sections = createMsvcRttiFixtureSections().slice(1);
  sections[0]!.virtualAddress = 0x1000;
  const reloc = writeMsvcRttiFixtureRelocations(view, new Set(fixture.relocations.blocks.flatMap(block =>
    block.entries.filter(entry => entry.type !== 0).map(entry => block.pageRva + entry.offset))), 0);
  writeMsvcRttiFixtureHeaders(bytes, view, 0x8664, 0x20b, sections, reloc.directorySize, false);
  return new MockFile(bytes);
};

const withClrHeader = (bytes: Uint8Array, runtimeHeaderRva = 0x3000): MockFile => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // PE32+ optional header at 0x98; data directories at +112, CLR is slot 14.
  // IMAGE_COR20_HEADER at RVA 0x3000 (raw 0x1400), cb=72, runtime version 2.5.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-clr-runtime-header-object-only
  view.setUint32(0x98 + 112 + 14 * 8, runtimeHeaderRva, true);
  view.setUint32(0x98 + 112 + 14 * 8 + 4, 72, true);
  view.setUint32(0x1400, 72, true);
  view.setUint16(0x1404, 2, true);
  view.setUint16(0x1406, 5, true);
  view.setUint32(0x1410, 1, true);
  return new MockFile(bytes);
};

export const managedMsvcPeFile = (): MockFile => withClrHeader(msvcDiscovery().fixture.bytes);

export const managedItaniumPeFile = (): MockFile => withClrHeader(createPeItaniumFixture().bytes);

export const managedNativeAotPeFile = async (): Promise<MockFile> =>
  withClrHeader(new Uint8Array(await nativeDiscoveryPeFile().arrayBuffer()), 0x2000);

export const reorderedNativeDiscovery = () => {
  const { fixture } = sparseNativeDiscovery();
  const bytes = new Uint8Array(fixture.bytes.length);
  bytes.set(fixture.bytes.subarray(0x10000), 0);
  bytes.set(fixture.bytes.subarray(0, 0x10000), 0x12000);
  const section = fixture.core.sections[0]!;
  fixture.core.sections.splice(0, 1,
    { ...section, virtualSize: 0x10000, sizeOfRawData: 0x10000, pointerToRawData: 0x12000 },
    { ...section, virtualAddress: 0x11000, virtualSize: 0x12000, sizeOfRawData: 0x12000, pointerToRawData: 0 });
  fixture.core.rvaToOff = rva => rva >= 0x11000 && rva < 0x23000 ? rva - 0x11000
    : rva >= 0x1000 && rva < 0x11000 ? 0x12000 + rva - 0x1000 : null;
  const state = createPeRelocationDiscovery(createMemoryRangeReader(bytes), fixture.core, fixture.relocations);
  assert.ok(state);
  return { state };
};

const hintContext = async (file: MockFile) => {
  const core = await parsePeHeaders(file);
  assert.ok(core && isPeWindowsCore(core));
  // Model normalized long COFF section names without coupling this test to the
  // unrelated COFF string-table decoder.
  core.sections[1]!.name = inlinePeSectionName(".managed");
  core.sections[2]!.name = inlinePeSectionName(".hydrated");
  return { file, core };
};

export const nativeAotHintContext = () => hintContext(msvcDiscovery().fixture.file);

export const managedAotHintContext = () => hintContext(managedMsvcPeFile());
