"use strict";

import { createPePlusWithSection } from "../../fixtures/sample-files-pe.js";
import { makeDotNetResources, stringResourceValue } from "../../fixtures/dotnet-resource-file.js";
import { createPngFile } from "../../fixtures/image-sample-files.js";
import { MockFile } from "../../helpers/mock-file.js";

const encoder = new TextEncoder();

const byteArrayValue = (bytes: Uint8Array): number[] => {
  const length = new Uint8Array(4);
  new DataView(length.buffer).setInt32(0, bytes.length, true);
  return [32, ...length, ...bytes];
};

const resourcePayloads = () => [
  { name: "Demo.resources", bytes: makeDotNetResources([
    ...Array.from({ length: 55 }, (_, index) => ({ name: `entry-${String(index).padStart(3, "0")}`,
      value: stringResourceValue(`value-${index}`) })),
    { name: "Greeting", value: stringResourceValue("Привет 世界") },
    { name: "Settings", value: stringResourceValue("<settings><message>Привет</message></settings>") },
    { name: "Image", value: byteArrayValue(createPngFile().data) },
    { name: "Broken", value: [8, 0] } // Int32 owns only one byte, before the next container boundary.
  ]) },
  { name: "Settings.xml", bytes: encoder.encode("<settings><language>ru</language></settings>") },
  ...Array.from({ length: 49 }, (_, index) => ({ name: `Text-${String(index).padStart(3, "0")}`,
    bytes: encoder.encode(`payload-${index}`) }))
];

const writeStream = (
  bytes: Uint8Array, header: number, name: string, offset: number, size: number
): void => {
  const view = new DataView(bytes.buffer);
  view.setUint32(header, offset, true);
  view.setUint32(header + 4, size, true);
  bytes.set(encoder.encode(`${name}\0`), header + 8);
};

const metadata = (names: string[], offsets: number[]): Uint8Array => {
  // ECMA-335 II.24.2 metadata root and streams; II.22 Module, Assembly, ManifestResource rows.
  // https://ecma-international.org/publications-and-standards/standards/ecma-335/
  const strings = ["", "ResourceSample.dll", "ResourceSample", ...names].map(name => encoder.encode(`${name}\0`));
  const indexes = strings.map((_, index) => strings.slice(0, index).reduce((sum, bytes) => sum + bytes.length, 0));
  const tableSize = 36 + 10 + 22 + names.length * 12;
  const stringsOffset = 80 + tableSize;
  const stringsSize = strings.reduce((sum, bytes) => sum + bytes.length, 0);
  const guidOffset = (stringsOffset + stringsSize + 3) & ~3;
  const bytes = new Uint8Array(guidOffset + 16);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0x424a5342, true); // BSJB.
  view.setUint16(4, 1, true);
  view.setUint16(6, 1, true);
  view.setUint32(12, 12, true);
  bytes.set(encoder.encode("v4.0.30319\0"), 16);
  view.setUint16(30, 3, true);
  writeStream(bytes, 32, "#~", 80, tableSize);
  writeStream(bytes, 44, "#Strings", stringsOffset, stringsSize);
  writeStream(bytes, 64, "#GUID", guidOffset, 16);
  view.setUint8(84, 2); // Tables major version.
  view.setUint8(87, 1); // Tables reserved byte.
  view.setBigUint64(88, 1n | (1n << 32n) | (1n << 40n), true);
  view.setUint32(104, 1, true);
  view.setUint32(108, 1, true);
  view.setUint32(112, names.length, true);
  view.setUint16(118, indexes[1]!, true); // Module.Name.
  view.setUint16(120, 1, true); // Module.Mvid = GUID #1.
  view.setUint32(126, 0x8004, true); // Assembly.HashAlgId = SHA-1.
  view.setUint16(130, 1, true); // Assembly.MajorVersion.
  view.setUint16(144, indexes[2]!, true); // Assembly.Name.
  names.forEach((_, index) => {
    const row = 148 + index * 12;
    view.setUint32(row, offsets[index]!, true);
    view.setUint32(row + 4, 1, true); // ManifestResource.Public.
    view.setUint16(row + 8, indexes[index + 3]!, true);
  });
  strings.forEach((string, index) => bytes.set(string, stringsOffset + indexes[index]!));
  bytes.set(Uint8Array.from({ length: 16 }, (_, index) => index + 1), guidOffset);
  return bytes;
};

export const createPeManagedResourceFile = (): MockFile => {
  const payloads = resourcePayloads();
  const offsets = payloads.map((_, index) => payloads.slice(0, index)
    .reduce((sum, payload) => sum + 4 + payload.bytes.length, 0));
  const resourcesSize = payloads.reduce((sum, payload) => sum + 4 + payload.bytes.length, 0);
  const meta = metadata(payloads.map(payload => payload.name), offsets);
  const bytes = new Uint8Array(0x10200);
  bytes.set(createPePlusWithSection());
  const view = new DataView(bytes.buffer);
  // Base fixture: PE32+, section RVA 0x1000, raw offset 0x200.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  const coff = view.getUint32(0x3c, true) + 4;
  const optional = coff + 20;
  const section = optional + view.getUint16(coff + 16, true);
  bytes.fill(0, optional + 112, optional + 112 + 16 * 8);
  view.setUint32(optional + 16, 0, true); // DLL has no native entry point.
  view.setUint32(optional + 56, 0x11000, true);
  view.setUint32(section + 8, 0x10000, true);
  view.setUint32(section + 16, 0x10000, true);
  view.setUint32(section + 36, 0x40000040, true); // Initialized, readable data section.
  view.setUint32(optional + 112 + 14 * 8, 0x1000, true);
  view.setUint32(optional + 112 + 14 * 8 + 4, 72, true);
  // ECMA-335 II.25.3.3: COR20 header, metadata directory (+8), resources directory (+24).
  bytes.fill(0, 0x200, 0x248);
  view.setUint32(0x200, 72, true);
  view.setUint16(0x204, 2, true);
  view.setUint16(0x206, 5, true);
  view.setUint32(0x208, 0x1100, true);
  view.setUint32(0x20c, meta.length, true);
  view.setUint32(0x210, 1, true);
  view.setUint32(0x218, 0x3000, true);
  view.setUint32(0x21c, resourcesSize, true);
  bytes.set(meta, 0x300);
  payloads.forEach((payload, index) => {
    const offset = 0x2200 + offsets[index]!;
    view.setUint32(offset, payload.bytes.length, true);
    bytes.set(payload.bytes, offset + 4);
  });
  return new MockFile(bytes, "managed-resources.dll");
};
