"use strict";

import { IMAGE_FILE_MACHINE_AMD64 } from "../../analyzers/coff/machine.js";
import type { PeBaseRelocationResult } from "../../analyzers/pe/directories/reloc.js";
import type { PeWindowsCore } from "../../analyzers/pe/types.js";
import { MockFile } from "../helpers/mock-file.js";
import {
  createMsvcRttiFixtureCore,
  createMsvcRttiFixtureSections,
  MSVC_RTTI_FIXTURE_FILE_SIZE,
  MSVC_RTTI_FIXTURE_IMAGE_BASE,
  MSVC_RTTI_FIXTURE_RDATA_RVA,
  MSVC_RTTI_FIXTURE_RDATA_SIZE,
  MSVC_RTTI_FIXTURE_TEXT_RVA,
  MSVC_RTTI_FIXTURE_TEXT_SIZE,
  msvcRttiFixtureRvaToOffset,
  writeMsvcRttiFixtureHeaders,
  writeMsvcRttiFixtureRelocations
} from "./pe-msvc-rtti-pe.js";
import {
  copyMsvcRttiFixtureHierarchy,
  flattenMsvcRttiFixtureNodes,
  msvcRttiFixtureDescendantCount,
  type MsvcRttiFixtureBase,
  type MsvcRttiFixtureHierarchy,
  type MsvcRttiFixtureHierarchyNode,
  type MsvcRttiFixtureType
} from "./pe-msvc-rtti-graph.js";

const BASE_CLASS_HAS_HIERARCHY = 0x40;

export interface MsvcRttiFixtureVftable {
  colRva: number;
  locatorSlotRva: number;
  rva: number;
  functionTargetRvas: number[];
}

export interface BuiltMsvcRttiFixture {
  bytes: Uint8Array;
  core: PeWindowsCore;
  file: MockFile;
  relocations: PeBaseRelocationResult | null;
  rvaToOffset: (rva: number) => number | null;
}

const alignUp = (value: number, alignment: number): number =>
  value + (alignment - value % alignment) % alignment;

export class MsvcRttiPeFixtureBuilder {
  readonly bytes = new Uint8Array(MSVC_RTTI_FIXTURE_FILE_SIZE);
  readonly view = new DataView(this.bytes.buffer);
  readonly sections = createMsvcRttiFixtureSections();
  #nextDataRva = MSVC_RTTI_FIXTURE_RDATA_RVA + 0x100;
  #nextFunctionRva = MSVC_RTTI_FIXTURE_TEXT_RVA;
  #dir64Sites = new Set<number>();
  #machine = IMAGE_FILE_MACHINE_AMD64;
  #optionalMagic = 0x20b;
  #omitRelocations = false;
  #relocationTailBytes = 0;
  #fileLength = MSVC_RTTI_FIXTURE_FILE_SIZE;

  allocateFunctionTarget(): number {
    if (
      this.#nextFunctionRva >= MSVC_RTTI_FIXTURE_TEXT_RVA + MSVC_RTTI_FIXTURE_TEXT_SIZE
    ) {
      throw new Error("Synthetic .text is full.");
    }
    const rva = this.#nextFunctionRva;
    this.#nextFunctionRva += 0x10;
    this.bytes[this.offsetOf(rva)] = 0xc3;
    return rva;
  }

  addType(decoratedName: string): MsvcRttiFixtureType {
    const encoded = new TextEncoder().encode(decoratedName);
    const rva = this.allocateData(16 + encoded.length + 1, 8);
    this.view.setBigUint64(
      this.offsetOf(rva),
      MSVC_RTTI_FIXTURE_IMAGE_BASE + BigInt(MSVC_RTTI_FIXTURE_TEXT_RVA),
      true
    );
    this.view.setBigUint64(this.offsetOf(rva + 8), 0n, true);
    this.bytes.set(encoded, this.offsetOf(rva + 16));
    this.#dir64Sites.add(rva);
    return { rva, nameRva: rva + 16, decoratedName };
  }

  addHierarchy(
    type: MsvcRttiFixtureType,
    bases: MsvcRttiFixtureBase[] = [],
    attributes = 0
  ): MsvcRttiFixtureHierarchy {
    const rva = this.allocateData(16, 4);
    const root: MsvcRttiFixtureHierarchyNode = {
      type,
      hierarchyRva: rva,
      pmd: { mdisp: 0, pdisp: -1, vdisp: 0 },
      attributes: BASE_CLASS_HAS_HIERARCHY,
      children: bases.map(base => copyMsvcRttiFixtureHierarchy(
        base.hierarchy,
        base.pmd ?? { mdisp: 0, pdisp: -1, vdisp: 0 },
        base.attributes ?? 0,
        BASE_CLASS_HAS_HIERARCHY
      ))
    };
    const nodes = flattenMsvcRttiFixtureNodes(root);
    const baseClassArrayRva = this.allocateData(nodes.length * 4, 4);
    const baseDescriptorRvas = nodes.map(() => this.allocateData(28, 4));
    this.writeHierarchy(rva, attributes, baseClassArrayRva, nodes, baseDescriptorRvas);
    return { rva, baseClassArrayRva, baseDescriptorRvas, type, root };
  }

  addVftable(
    hierarchy: MsvcRttiFixtureHierarchy,
    functionTargetRvas: number[],
    offset = 0,
    cdOffset = 0
  ): MsvcRttiFixtureVftable {
    const colRva = this.allocateData(24, 4);
    this.writeCompleteObjectLocator(colRva, hierarchy, offset, cdOffset);
    const locatorSlotRva = this.allocateData((functionTargetRvas.length + 1) * 8, 8);
    this.writePreferredVa(locatorSlotRva, colRva);
    this.#dir64Sites.add(locatorSlotRva);
    functionTargetRvas.forEach((targetRva, index) => {
      const slotRva = locatorSlotRva + (index + 1) * 8;
      this.writePreferredVa(slotRva, targetRva);
      this.#dir64Sites.add(slotRva);
    });
    return { colRva, locatorSlotRva, rva: locatorSlotRva + 8, functionTargetRvas };
  }

  addDir64Pointer(targetRva: number): number {
    const siteRva = this.allocateData(8, 8);
    this.writePreferredVa(siteRva, targetRva);
    this.#dir64Sites.add(siteRva);
    return siteRva;
  }

  allocateData(size: number, alignment = 4): number {
    const rva = alignUp(this.#nextDataRva, alignment);
    if (rva + size > MSVC_RTTI_FIXTURE_RDATA_RVA + MSVC_RTTI_FIXTURE_RDATA_SIZE) {
      throw new Error("Synthetic .rdata is full.");
    }
    this.#nextDataRva = rva + size;
    return rva;
  }

  patchUint32(rva: number, relativeOffset: number, value: number): void {
    this.view.setUint32(this.offsetOf(rva + relativeOffset), value, true);
  }

  patchInt32(rva: number, relativeOffset: number, value: number): void {
    this.view.setInt32(this.offsetOf(rva + relativeOffset), value, true);
  }

  patchBigUint64(rva: number, value: bigint): void {
    this.view.setBigUint64(this.offsetOf(rva), value, true);
  }

  patchByte(rva: number, value: number): void {
    this.bytes[this.offsetOf(rva)] = value;
  }

  removeDir64Site(rva: number): void {
    this.#dir64Sites.delete(rva);
  }

  setMachine(machine: number): void {
    this.#machine = machine;
  }

  setOptionalMagic(magic: number): void {
    this.#optionalMagic = magic;
  }

  omitBaseRelocations(): void {
    this.#omitRelocations = true;
  }

  appendRelocationTail(byteCount: number): void {
    this.#relocationTailBytes = byteCount;
  }

  truncateAtRva(rva: number): void {
    this.#fileLength = this.offsetOf(rva);
  }

  build(): BuiltMsvcRttiFixture {
    const relocations = this.#omitRelocations
      ? null
      : writeMsvcRttiFixtureRelocations(this.view, this.#dir64Sites, this.#relocationTailBytes);
    writeMsvcRttiFixtureHeaders(
      this.bytes,
      this.view,
      this.#machine,
      this.#optionalMagic,
      this.sections,
      relocations?.directorySize ?? 0,
      this.#omitRelocations
    );
    const bytes = this.bytes.slice(0, this.#fileLength);
    const file = new MockFile(bytes, "msvc-rtti-fixture.exe", "application/vnd.microsoft.portable-executable");
    return {
      bytes,
      core: createMsvcRttiFixtureCore(
        this.#machine,
        this.#optionalMagic,
        this.sections,
        this.#omitRelocations
      ),
      file,
      relocations: this.#omitRelocations ? null : relocations?.model ?? null,
      rvaToOffset: msvcRttiFixtureRvaToOffset
    };
  }

  offsetOf(rva: number): number {
    const offset = msvcRttiFixtureRvaToOffset(rva);
    if (offset == null) throw new Error(`RVA 0x${rva.toString(16)} is not file-backed.`);
    return offset;
  }

  private writeHierarchy(
    rva: number,
    attributes: number,
    baseClassArrayRva: number,
    nodes: MsvcRttiFixtureHierarchyNode[],
    descriptorRvas: number[]
  ): void {
    this.patchUint32(rva, 0, 0);
    this.patchUint32(rva, 4, attributes);
    this.patchUint32(rva, 8, nodes.length);
    this.patchUint32(rva, 12, baseClassArrayRva);
    nodes.forEach((node, index) => {
      this.patchUint32(baseClassArrayRva, index * 4, descriptorRvas[index]!);
      this.writeBaseClassDescriptor(descriptorRvas[index]!, node);
    });
  }

  private writeBaseClassDescriptor(rva: number, node: MsvcRttiFixtureHierarchyNode): void {
    this.patchUint32(rva, 0, node.type.rva);
    this.patchUint32(rva, 4, msvcRttiFixtureDescendantCount(node));
    this.patchInt32(rva, 8, node.pmd.mdisp);
    this.patchInt32(rva, 12, node.pmd.pdisp);
    this.patchInt32(rva, 16, node.pmd.vdisp);
    this.patchUint32(rva, 20, node.attributes);
    this.patchUint32(rva, 24, node.hierarchyRva);
  }

  private writeCompleteObjectLocator(
    rva: number,
    hierarchy: MsvcRttiFixtureHierarchy,
    offset: number,
    cdOffset: number
  ): void {
    this.patchUint32(rva, 0, 1);
    this.patchUint32(rva, 4, offset);
    this.patchUint32(rva, 8, cdOffset);
    this.patchUint32(rva, 12, hierarchy.type.rva);
    this.patchUint32(rva, 16, hierarchy.rva);
    this.patchUint32(rva, 20, rva);
  }

  private writePreferredVa(siteRva: number, targetRva: number): void {
    this.view.setBigUint64(
      this.offsetOf(siteRva),
      MSVC_RTTI_FIXTURE_IMAGE_BASE + BigInt(targetRva),
      true
    );
  }
}

export const createSimpleMsvcRttiFixture = (slotCount = 1): {
  builder: MsvcRttiPeFixtureBuilder;
  hierarchy: MsvcRttiFixtureHierarchy;
  type: MsvcRttiFixtureType;
  vftable: MsvcRttiFixtureVftable;
} => {
  const builder = new MsvcRttiPeFixtureBuilder();
  const type = builder.addType(".?AVSimple@@");
  const hierarchy = builder.addHierarchy(type);
  const targets = Array.from({ length: slotCount }, () => builder.allocateFunctionTarget());
  const vftable = builder.addVftable(hierarchy, targets);
  return { builder, hierarchy, type, vftable };
};
