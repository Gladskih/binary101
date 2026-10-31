import { createPePlusWithSection } from "./sample-files-pe.js";
import { createSymbolTable } from "./pe-coff-debug-fixtures.js";
import { resourceRcc } from "./embedded-rcc.js";
import { resourceGResource } from "./embedded-gresource.js";

// Microsoft PE/COFF section headers and COFF long-name string table.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
const writeSection = (bytes: Uint8Array, index: number, name: string,
  raw: number, size: number): void => {
  const view = new DataView(bytes.buffer);
  const offset = 0x148 + index * 40;
  bytes.fill(0, offset, offset + 40);
  bytes.set(new TextEncoder().encode(name), offset);
  view.setUint32(offset + 8, size, true);
  view.setUint32(offset + 12, 0x1000 + index * 0x1000, true);
  view.setUint32(offset + 16, size, true);
  view.setUint32(offset + 20, raw, true);
  view.setUint32(offset + 36, 0x40000040, true);
};

export const resourcePe = (): Uint8Array => {
  const rcc = resourceRcc(3);
  const view = new DataView(rcc.buffer);
  const data = Uint8Array.from([...rcc.slice(24), ...rcc, ...resourceGResource()]);
  const rawSize = Math.ceil(data.length / 512) * 512;
  const symbolOffset = 512 + rawSize + 512;
  const table = createSymbolTable([
    { name: ".file", storageClass: 103, sectionNumber: -2 },
    { name: "qt_resource_data", value: view.getUint32(12) - 24, storageClass: 3 },
    { name: "qt_resource_name", value: view.getUint32(16) - 24, storageClass: 3 },
    { name: "qt_resource_struct", value: view.getUint32(8) - 24, storageClass: 3 },
    { name: "arrays_end", value: rcc.length - 24, storageClass: 3 }
  ], [".gresource.oracle", "qt_resource_data", "qt_resource_name", "qt_resource_struct", "arrays_end"]);
  const bytes = new Uint8Array(symbolOffset + table.bytes.length);
  bytes.set(createPePlusWithSection().slice(0, 512));
  const image = new DataView(bytes.buffer);
  image.setUint16(0x46, 2, true);
  image.setUint32(0x4c, symbolOffset, true);
  image.setUint32(0x50, table.recordCount, true);
  image.setUint32(0x90, 0x3000, true); // SizeOfImage.
  bytes.fill(0, 0xc8, 0x148); // All data directories are absent in this fixture.
  writeSection(bytes, 0, ".rdata", 512, rawSize);
  writeSection(bytes, 1, "/4", 512 + rawSize, 512);
  bytes.set(data, 512);
  bytes.set(resourceGResource(), 512 + rawSize);
  bytes.set(table.bytes, symbolOffset);
  return bytes;
};
