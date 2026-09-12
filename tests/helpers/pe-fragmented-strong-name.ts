import { createRvaToOffsetMapper } from "../../analyzers/pe/sections/rva-mapper.js";
import { COFF_SECTION_HEADER_BYTE_LENGTH } from "../../analyzers/coff/layout.js";
import {
  makeClr, makePublicKeyBlob, makeStrongNamePeFixture, makeStrongNameKeyPair, signStrongNameInput
} from "./pe-strong-name-fixture.js";
import type { PeSection } from "../../analyzers/pe/types.js";

const writeSection = (
  bytes: Uint8Array, headerOffset: number, section: PeSection, contentByte: number
): void => {
  const view = new DataView(bytes.buffer);
  // IMAGE_SECTION_HEADER: VirtualSize +8, VirtualAddress +12, SizeOfRawData +16,
  // PointerToRawData +20. https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  view.setUint32(headerOffset + 8, section.virtualSize, true);
  view.setUint32(headerOffset + 12, section.virtualAddress, true);
  view.setUint32(headerOffset + 16, section.sizeOfRawData, true);
  view.setUint32(headerOffset + 20, section.pointerToRawData, true);
  bytes.fill(contentByte, section.pointerToRawData, section.pointerToRawData + section.sizeOfRawData);
};

const makeSectionHeaders = (
  base: ReturnType<typeof makeStrongNamePeFixture>, storageOrder: [number, number]
): PeSection[] => storageOrder.map((slot, index) => ({
  name: { kind: "inline", value: ".text" },
  // Keep section RVAs adjacent while leaving a file-sized gap between raw ranges.
  virtualAddress: base.layout.sectionRawPointer + index * base.layout.signatureSize,
  virtualSize: base.layout.signatureSize,
  sizeOfRawData: base.layout.signatureSize,
  pointerToRawData: base.layout.sectionRawPointer + slot * base.bytes.length,
  characteristics: 0
}));

const signingInput = (
  bytes: Uint8Array, headerEnd: number, sections: PeSection[]
): Uint8Array => Uint8Array.from([
  ...bytes.subarray(0, headerEnd),
  ...bytes.subarray(sections[0]!.pointerToRawData,
    sections[0]!.pointerToRawData + sections[0]!.sizeOfRawData / 2),
  ...bytes.subarray(sections[1]!.pointerToRawData + sections[1]!.sizeOfRawData / 2,
    sections[1]!.pointerToRawData + sections[1]!.sizeOfRawData)
]);

const writeSignature = (bytes: Uint8Array, signature: Uint8Array, sections: PeSection[]): void => {
  bytes.set(signature.subarray(0, signature.length / 2),
    sections[0]!.pointerToRawData + sections[0]!.sizeOfRawData / 2);
  bytes.set(signature.subarray(signature.length / 2), sections[1]!.pointerToRawData);
};

export const makeFragmentedSignedFixture = async (storageOrder: [number, number] = [0, 1]) => {
  const base = makeStrongNamePeFixture();
  const sections = makeSectionHeaders(base, storageOrder);
  const bytes = new Uint8Array(Math.max(...sections.map(section =>
    section.pointerToRawData + section.sizeOfRawData)));
  bytes.set(base.bytes.subarray(0, base.layout.sectionHeaderOffset));
  // IMAGE_FILE_HEADER.NumberOfSections is at NT-header offset +6.
  new DataView(bytes.buffer).setUint16(base.layout.ntHeadersOffset + 6, sections.length, true);
  // Distinct contents make section reordering detectable by signature verification.
  sections.forEach((section, index) => writeSection(bytes,
    base.layout.sectionHeaderOffset + index * COFF_SECTION_HEADER_BYTE_LENGTH, section, index + 1));
  const keys = await makeStrongNameKeyPair();
  // Independent oracle: headers, section 1 prefix, section 2 suffix, in header order.
  // https://source.dot.net/Microsoft.DotNet.StrongName/Utils.cs.html (ComputeSigningHash)
  writeSignature(bytes, await signStrongNameInput(keys.privateKey, signingInput(bytes,
    base.layout.sectionHeaderOffset + sections.length * COFF_SECTION_HEADER_BYTE_LENGTH,
    sections)), sections);
  return {
    bytes, mapping: createRvaToOffsetMapper(sections, bytes.length, 0, 0),
    clr: makeClr(sections[0]!.virtualAddress + base.layout.signatureSize / 2,
      base.layout.signatureSize, await makePublicKeyBlob(keys.publicKey))
  };
};
