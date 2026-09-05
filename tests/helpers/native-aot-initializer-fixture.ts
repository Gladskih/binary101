import type { NativeAotMetadata } from "../../analyzers/native-aot/format.js";
import type { NativeAotVirtualImage } from "../../analyzers/native-aot/virtual-image-types.js";

// RunInitializers: signed int32 displacement, relative to the address of its own slot.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Common/src/Internal/Runtime/CompilerHelpers/StartupCodeHelpers.cs
export const writeInitializerTarget = (
  view: DataView, offset: number, slotRva: number, targetRva: number
): void => view.setInt32(offset, targetRva - slotRva, true);

export const createNativeAotInitializerFixture = (pointerSize: 4 | 8 = 8) => {
  // Leave a nonzero code address before the table, then reserve backward/forward/duplicate slots.
  const tableRva = pointerSize * 2;
  const bytes = new Uint8Array(Int32Array.BYTES_PER_ELEMENT * 3);
  const codeRvas: [number, number] = [pointerSize, tableRva + bytes.length];
  const view = new DataView(bytes.buffer);
  [codeRvas[0], codeRvas[1], codeRvas[0]].forEach((target, index) => {
    const offset = index * Int32Array.BYTES_PER_ELEMENT;
    writeInitializerTarget(view, offset, tableRva + offset, target);
  });
  const image: NativeAotVirtualImage = {
    pointerSize,
    isDataRange: (address, size, alignment) => address === tableRva &&
      size <= bytes.length && size > 0 && address % alignment === 0,
    isMappedRange: () => true,
    isExecutableAddress: address => codeRvas.includes(address),
    readData: async (address, size) => new DataView(bytes.buffer, address - tableRva, size),
    readPointerTarget: async () => null,
    readPointerValue: async () => null
  };
  return { image, codeRvas, header: createInitializerHeader(tableRva, bytes.length, pointerSize) };
};

const createInitializerHeader = (
  tableRva: number, tableSize: number, pointerSize: number
): NativeAotMetadata => ({
  status: "confirmed", layout: "nativeaot-readytorun-pointer-range-v1",
  modulePointerRva: tableRva + tableSize + pointerSize,
  headerRva: tableRva + tableSize + pointerSize * 2,
  // Independent format oracle: .NET 10 version 16.0, EagerCctor section 205.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/ModuleHeaders.cs
  majorVersion: 16, minorVersion: 0,
  sections: [{ type: 205, rva: tableRva, size: tableSize }]
});

export const createChunkedInitializerFixture = (size: number, reads: number[]) => {
  const fixture = createNativeAotInitializerFixture();
  fixture.header.sections[0]!.size = size;
  fixture.image.isDataRange = () => true;
  fixture.image.readData = async (address, length) => {
    reads.push(length);
    const view = new DataView(new ArrayBuffer(length));
    for (let offset = 0; offset < length; offset += Int32Array.BYTES_PER_ELEMENT) {
      writeInitializerTarget(view, offset, address + offset, fixture.codeRvas[0]);
    }
    return view;
  };
  return fixture;
};
