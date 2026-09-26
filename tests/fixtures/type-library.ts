import type { ResourceTypeLibrarySegmentPreview } from "../../analyzers/pe/resources/preview/types.js";
import { TypeLibraryReader } from "../../analyzers/pe/type-library/reader.js";

// Fixture layouts are independently encoded from Wine typelib.h / typelib.c.
// https://github.com/wine-mirror/wine/tree/master/dlls/oleaut32
export const createLibraryReader = (name: string, size = 128): TypeLibraryReader =>
  new TypeLibraryReader(new Uint8Array(size), [{ name, offset: 0, length: size }], []);

export const createDescriptorChain = (count: number): TypeLibraryReader => {
  const reader = createLibraryReader("TypdescTab", count * 8);
  for (let index = 0; index < count; index++) {
    reader.view.setUint16(index * 8, 26, true);
    reader.view.setInt32(index * 8 + 4, index === count - 1 ? -2147483645 : (index + 1) * 8, true);
  }
  return reader;
};

export const createMsftLibrary = (): Uint8Array => {
  const data = new Uint8Array(2200);
  const view = new DataView(data.buffer);
  data.set(new TextEncoder().encode("MSFT"));
  view.setUint32(4, 0x10002, true);
  view.setUint32(12, 0x409, true);
  view.setUint32(20, 1, true);
  view.setUint32(24, 0x20001, true);
  view.setUint32(32, 4, true);
  view.setInt32(36, 0, true);
  view.setInt32(60, -1, true);
  view.setInt32(64, 0, true);
  const segments: ResourceTypeLibrarySegmentPreview[] = [
    { name: "TypeInfoTab", offset: 512, length: 400 },
    { name: "NameTab", offset: 1024, length: 0 },
    { name: "GuidTab", offset: 1200, length: 96 },
    { name: "StringTab", offset: 1320, length: 12 },
    { name: "TypdescTab", offset: 1400, length: 32 },
    { name: "ImpFiles", offset: 1450, length: 20 },
    { name: "ImpInfo", offset: 1490, length: 12 },
    { name: "RefTab", offset: 1520, length: 32 },
    { name: "CustData", offset: 1560, length: 40 },
    { name: "CDGuids", offset: 1620, length: 24 },
    { name: "ArrayDescriptions", offset: 1660, length: 24 }
  ];
  const names = writeNames(view, data);
  segments[1]!.length = names.length;
  const order = ["TypeInfoTab", "ImpInfo", "ImpFiles", "RefTab", "GuidHashTab", "GuidTab",
    "NameHashTab", "NameTab", "StringTab", "TypdescTab", "ArrayDescriptions", "CustData",
    "CDGuids", "Reserved0E", "Reserved0F"];
  for (let index = 0; index < order.length; index++) {
    const segment = segments.find(entry => entry.name === order[index]);
    view.setInt32(100 + index * 16, segment?.offset ?? -1, true);
    view.setInt32(104 + index * 16, segment?.length ?? 0, true);
  }
  for (let index = 0; index < 4; index++) {
    view.setUint32(84 + index * 4, index * 100, true);
    const start = 512 + index * 100;
    view.setUint32(start, [3, 6, 2, 5][index]! | (4 << 11), true);
    view.setInt32(start + 44, index * 24, true);
    view.setInt32(start + 52, names.offsets[index + 1]!, true);
    view.setUint32(start + 56, 0x10001, true);
    view.setInt32(start + 60, 0, true);
    view.setInt32(start + 72, -1, true);
    view.setUint32(start + 80, 16, true);
  }
  view.setInt32(56, names.offsets[0]!, true);
  view.setUint32(516, 1800, true);
  view.setUint32(536, 0x10001, true);
  view.setUint16(588, 1, true);
  view.setUint16(590, 8, true);
  view.setInt32(596, 1, true);
  view.setInt32(696, -2147483623, true); // inline VT_HRESULT (0x80000019)
  view.setInt32(796, 0, true);
  view.setUint16(888, 1, true);
  view.setInt32(896, 0, true);
  view.setUint16(1320, 7, true);
  data.set(new TextEncoder().encode("Example"), 1322);
  view.setUint16(1400, 26, true);
  view.setInt32(1404, -2147483645, true); // inline VT_I4
  view.setUint16(1408, 29, true);
  view.setInt32(1412, 1, true);
  view.setUint16(1416, 28, true);
  view.setUint16(1424, 27, true);
  view.setInt32(1428, 0, true);
  view.setInt32(1450, 0, true);
  view.setUint32(1458, 0x20001, true);
  view.setUint16(1462, 5 << 2, true);
  data.set(new TextEncoder().encode("a.tlb"), 1464);
  view.setUint32(1490, 0x10000 | (3 << 24), true);
  view.setInt32(1498, 24, true);
  view.setInt32(1520, 0, true);
  view.setUint32(1524, 3, true);
  view.setInt32(1528, -1, true);
  view.setInt32(1532, -1, true);
  view.setUint16(1560, 3, true);
  view.setInt32(1562, -123, true);
  view.setUint16(1568, 8, true);
  view.setInt32(1570, 3, true);
  data.set(new TextEncoder().encode("yes"), 1574);
  view.setInt32(1624, 0, true);
  view.setInt32(1628, -1, true);
  view.setInt32(1660, -2147483645, true);
  view.setUint16(1664, 1, true);
  view.setUint32(1668, 3, true);
  view.setInt32(1672, -1, true);
  writeMembers(view, names.offsets);
  return data;
};

const writeNames = (view: DataView, data: Uint8Array): { offsets: number[]; length: number } => {
  const offsets: number[] = [];
  let cursor = 0;
  for (const name of ["Lib", "ITest", "Alias", "Module", "Class", "Run", "Value", "arg"]) {
    const bytes = new TextEncoder().encode(name);
    offsets.push(cursor);
    view.setUint8(1024 + cursor + 8, bytes.length);
    data.set(bytes, 1024 + cursor + 12);
    cursor += Math.ceil((12 + bytes.length) / 4) * 4;
  }
  return { offsets, length: cursor };
};

const writeMembers = (view: DataView, names: number[]): void => {
  view.setUint32(1800, 68, true);
  view.setUint32(1804, 48, true);
  view.setInt32(1808, 0, true);
  view.setUint16(1816, 8, true);
  view.setUint32(1820, 0x1000 | (4 << 8) | (1 << 3) | 1, true);
  view.setUint16(1824, 1, true);
  view.setUint16(1826, 1, true);
  view.setInt32(1832, 0, true);
  view.setInt32(1836, -1946157014, true); // packed VT_I4 + 42 = 0x8c00002a
  view.setInt32(1840, 8, true);
  view.setInt32(1844, names[7]!, true);
  view.setUint32(1848, 0x31, true);
  view.setUint32(1852, 20, true);
  view.setInt32(1856, -2147483645, true);
  view.setUint16(1864, 2, true);
  view.setInt32(1868, 0, true);
  view.setInt32(1872, 7, true);
  view.setInt32(1876, 8, true);
  view.setInt32(1880, names[5]!, true);
  view.setInt32(1884, names[6]!, true);
  view.setInt32(1888, 0, true);
  view.setInt32(1892, 48, true);
};
