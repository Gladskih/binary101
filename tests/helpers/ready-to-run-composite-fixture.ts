import { MockFile } from "./mock-file.js";
import type { PeClrHeader } from "../../analyzers/pe/clr/types.js";
import type { PeClrReadyToRun, PeClrReadyToRunComponent } from "../../analyzers/pe/clr/ready-to-run-types.js";

export const createReadyToRunCompositeFixture = () => {
  const bytes = new Uint8Array(0x400);
  const view = new DataView(bytes.buffer);
  // readytorun.h: component core headers have two DWORDs, followed by 12-byte directories.
  view.setUint32(0x100, 0x20, true);
  view.setUint32(0x104, 1, true);
  view.setUint32(0x108, 103, true);
  view.setUint32(0x10c, 0x180, true);
  view.setUint32(0x110, 4, true);
  bytes.set([8, 1, 0, 4], 0x180);
  const component: PeClrReadyToRunComponent =
    { clrRva: 0, clrSize: 0, coreHeaderRva: 0x100, coreHeaderSize: 20 };
  const data: PeClrReadyToRun = { status: "ready-to-run", signature: 0x00525452,
    majorVersion: 16, minorVersion: 0, flags: 0, sectionCount: 2, issues: [], sections: [
      { type: 102, name: "RuntimeFunctions", rva: 0x200, size: 12 },
      { type: 115, name: "ComponentAssemblies", rva: 0x80, size: 16,
        decoded: { kind: "components", entries: [component] } }
    ] };
  const clr = { ManagedNativeHeaderRVA: 0x20, ManagedNativeHeaderSize: 40 } as PeClrHeader;
  view.setUint32(0x20, 0x00525452, true);
  view.setUint16(0x24, 16, true);
  view.setUint32(0x2c, 2, true);
  data.sections.forEach((section, index) => {
    view.setUint32(0x30 + index * 12, section.type, true);
    view.setUint32(0x34 + index * 12, section.rva, true);
    view.setUint32(0x38 + index * 12, section.size, true);
  });
  view.setUint32(0x88, component.coreHeaderRva, true);
  view.setUint32(0x8c, component.coreHeaderSize, true);
  return { bytes, view, reader: new MockFile(bytes), data, component, clr };
};

export const createLargeReadyToRunDirectoryFixture = () => {
  const count = 6000;
  const bytes = new Uint8Array(count * 12);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < count; index++) view.setUint32(index * 12, 10000 + index, true);
  return { count, reader: new MockFile(bytes) };
};
