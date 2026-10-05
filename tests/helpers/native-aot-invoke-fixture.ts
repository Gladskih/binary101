import type { NativeAotMetadataSection } from "../../analyzers/native-aot/format.js";
import type { NativeAotVirtualImage } from "../../analyzers/native-aot/virtual-image-types.js";
import { createNativeHashtableFixture } from "./native-hashtable-fixture.js";

export const createNativeAotInvokeFixture = () => {
  // NativeFormat uint values are doubled in their one-byte encoding.
  // HasEntrypoint=0x20, IsGenericMethod=2, common fixup indices 0 (body), 1 (invoke stub).
  const map = createNativeHashtableFixture([Uint8Array.of(68, 20, 8, 0, 2, 4, 6, 8)]);
  const mapRva = 0x100;
  const fixupsRva = 0x200;
  const codeRvas = [0x40, 0x300];
  const bytes = new Uint8Array(0x400);
  bytes.set(map, mapRva);
  const view = new DataView(bytes.buffer);
  view.setInt32(fixupsRva, codeRvas[0]! - fixupsRva, true);
  view.setInt32(fixupsRva + 4, codeRvas[1]! - fixupsRva - 4, true);
  const image: NativeAotVirtualImage = { pointerSize: 8,
    isDataRange: (address, size, alignment) => address >= 0 && size > 0 &&
      size <= bytes.length - address && address % alignment === 0,
    isMappedRange: (address, size) => address >= 0 && size > 0 && size <= bytes.length - address,
    isExecutableAddress: address => codeRvas.includes(address),
    readData: async (address, size, alignment) => address % alignment === 0 &&
      address >= 0 && size <= bytes.length - address ? new DataView(bytes.buffer, address, size) : null,
    readPointerValue: async () => null, readPointerTarget: async () => null };
  const sections: NativeAotMetadataSection[] = [
    { type: 306, rva: mapRva, size: map.length }, { type: 308, rva: fixupsRva, size: 8 }
  ];
  return { image, sections, bytes, view, mapRva, fixupsRva, codeRvas };
};
