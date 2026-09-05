import { COFF_SECTION_CHARACTERISTICS } from "../../analyzers/coff/layout.js";
import { createNativeAotMetadataFixture } from "./pe-native-aot-metadata-fixture.js";
import { writeInitializerTarget } from "./native-aot-initializer-fixture.js";

const readPreferredPointer = (view: DataView, offset: number, pointerSize: 4 | 8): bigint =>
  pointerSize === 8 ? view.getBigUint64(offset, true) : BigInt(view.getUint32(offset, true));

export const createPeNativeAotInitializerFixture = (pointerSize: 4 | 8 = 8) => {
  const fixture = createNativeAotMetadataFixture(pointerSize);
  const dataSection = fixture.core.sections[0]!;
  const codeRva = fixture.embeddedMetadataRva + fixture.metadataSize;
  const codeOffset = fixture.core.rvaToOff(codeRva)!;
  dataSection.virtualSize = dataSection.sizeOfRawData = codeRva - dataSection.virtualAddress;
  fixture.core.sections.push({ ...dataSection, virtualAddress: codeRva,
    pointerToRawData: codeOffset, virtualSize: fixture.bytes.length - codeOffset,
    sizeOfRawData: fixture.bytes.length - codeOffset,
    characteristics: COFF_SECTION_CHARACTERISTICS.CNT_CODE |
      COFF_SECTION_CHARACTERISTICS.MEM_READ | COFF_SECTION_CHARACTERISTICS.MEM_EXECUTE });
  // ModuleHeaders.cs: 16-byte RTR header, followed by section entries; EagerCctor = 205.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/ModuleHeaders.cs
  const entryOffset = fixture.core.rvaToOff(fixture.headerRva)! + 16;
  fixture.view.setUint32(entryOffset, 205, true);
  // Pointer-range entry: uint32 type, uint32 flags, then start and end native pointers.
  // https://github.com/dotnet/runtime/blob/v9.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/ReadyToRunHeaderNode.cs
  const startSlot = entryOffset + Uint32Array.BYTES_PER_ELEMENT * 2;
  const tableRva = Number(readPreferredPointer(fixture.view, startSlot, pointerSize) -
    fixture.core.opt.ImageBase);
  const tableEndRva = Number(readPreferredPointer(fixture.view, startSlot + pointerSize, pointerSize) -
    fixture.core.opt.ImageBase);
  const setInitializerTarget = (index: number, targetRva: number): void => {
    const slotRva = tableRva + index * Int32Array.BYTES_PER_ELEMENT;
    writeInitializerTarget(fixture.view, fixture.core.rvaToOff(slotRva)!, slotRva, targetRva);
  };
  for (let index = 0; index < (tableEndRva - tableRva) / Int32Array.BYTES_PER_ELEMENT; index += 1) {
    setInitializerTarget(index, codeRva);
  }
  return { ...fixture, codeRva, setInitializerTarget };
};
