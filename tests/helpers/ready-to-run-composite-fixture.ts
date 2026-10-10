import { MockFile } from "./mock-file.js";
import type { PeClrHeader } from "../../analyzers/pe/clr/types.js";
import type { PeClrReadyToRun, PeClrReadyToRunComponent } from "../../analyzers/pe/clr/ready-to-run-types.js";

export const createReadyToRunCompositeFixture = () => {
  const managedHeaderRva = 0x20;
  const componentTableRva = 0x80;
  const coreHeaderRva = 0x100;
  const methodMapRva = 0x180;
  const directoryEntrySize = 12;
  const coreHeaderSize = 8 + directoryEntrySize;
  const bytes = new Uint8Array(0x400);
  const view = new DataView(bytes.buffer);
  // A core header has flags and section count before 12-byte section directory records.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/readytorun.h
  // READYTORUN_FLAG_COMPONENT marks this per-assembly header in a composite image.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/readytorun.h
  view.setUint32(coreHeaderRva, 0x20, true);
  view.setUint32(coreHeaderRva + 4, 1, true);
  view.setUint32(coreHeaderRva + 8, 103, true);
  view.setUint32(coreHeaderRva + 12, methodMapRva, true);
  view.setUint32(coreHeaderRva + 16, 4, true);
  // One-entry MethodDefEntryPoints NativeArray: header, index, leaf, no-fixup index 1.
  bytes.set([8, 1, 0, 4], methodMapRva);
  const component: PeClrReadyToRunComponent =
    { clrRva: 0, clrSize: 0, coreHeaderRva, coreHeaderSize };
  const sections: PeClrReadyToRun["sections"] = [
      { type: 102, name: "RuntimeFunctions", rva: 0x200, size: directoryEntrySize },
      { type: 115, name: "ComponentAssemblies", rva: componentTableRva, size: 8 * 2,
        decoded: { kind: "components", entries: [component] } }
  ];
  const data: PeClrReadyToRun = { status: "ready-to-run", signature: 0x00525452,
    majorVersion: 16, minorVersion: 0, flags: 0, sectionCount: sections.length, issues: [], sections };
  // ManagedNativeHeader: signature, version, flags, section count, then 12-byte records.
  const clr = { ManagedNativeHeaderRVA: managedHeaderRva,
    ManagedNativeHeaderSize: 16 + directoryEntrySize * data.sections.length } as PeClrHeader;
  view.setUint32(managedHeaderRva, 0x00525452, true);
  view.setUint16(managedHeaderRva + 4, 16, true);
  view.setUint32(managedHeaderRva + 12, data.sections.length, true);
  data.sections.forEach((section, index) => {
    const directory = managedHeaderRva + 16 + index * directoryEntrySize;
    view.setUint32(directory, section.type, true);
    view.setUint32(directory + 4, section.rva, true);
    view.setUint32(directory + 8, section.size, true);
  });
  // The component row stores its core header RVA and byte size after two DWORD fields.
  view.setUint32(componentTableRva + 8, component.coreHeaderRva, true);
  view.setUint32(componentTableRva + 12, component.coreHeaderSize, true);
  return { bytes, view, reader: new MockFile(bytes), data, component, clr,
    componentTableRva, coreHeaderRva, coreHeaderSize, methodMapRva };
};

export const createLargeReadyToRunDirectoryFixture = () => {
  const count = 6000;
  const bytes = new Uint8Array(count * 12);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < count; index++) view.setUint32(index * 12, 10000 + index, true);
  return { count, reader: new MockFile(bytes) };
};
