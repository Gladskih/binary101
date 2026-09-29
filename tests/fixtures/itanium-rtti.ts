import type { ItaniumRttiImage } from "../../analyzers/itanium-rtti/types.js";

// Independent synthetic layout, following Itanium ABI 2.9.5 and GCC cxxabi.h.
export const createItaniumFixture = (pointerSize: 4 | 8 = 8) => {
  const bytes = new Uint8Array(4096);
  const view = new DataView(bytes.buffer);
  const pointers = new Map<number, number>();
  const relocations = new Set<number>();
  const addresses = { classTable: 128, siTable: 192, vmiTable: 256,
    classMeta: 320, siMeta: 384, vmiMeta: 448, stdMeta: 512,
    base: 576, derived: 640, multiple: 704, table: 832, siObjectTable: 896,
    vmiObjectTable: 960, code: 8192 };
  let nextName = 1100;
  const pointer = (site: number, target: number): void => {
    pointers.set(site, target);
    relocations.add(site);
    if (pointerSize === 8) view.setBigUint64(site, BigInt(target), true);
    else view.setUint32(site, target, true);
  };
  const word = (site: number, value: bigint): void => {
    if (pointerSize === 8) view.setBigInt64(site, value, true);
    else view.setInt32(site, Number(value), true);
  };
  const type = (address: number, table: number, name: string): void => {
    pointer(address, table);
    pointer(address + pointerSize, nextName);
    bytes.set(new TextEncoder().encode(name + "\0"), nextName);
    nextName += name.length + 1;
  };
  const table = (address: number, typeAddress: number): void => {
    pointer(address - pointerSize, typeAddress);
    pointer(address, addresses.code);
    pointer(address + pointerSize, addresses.code + 16);
  };
  table(addresses.classTable, addresses.classMeta);
  table(addresses.siTable, addresses.siMeta);
  table(addresses.vmiTable, addresses.vmiMeta);
  type(addresses.classMeta, addresses.siTable, "N10__cxxabiv117__class_type_infoE");
  type(addresses.siMeta, addresses.siTable, "N10__cxxabiv120__si_class_type_infoE");
  type(addresses.vmiMeta, addresses.siTable, "N10__cxxabiv121__vmi_class_type_infoE");
  type(addresses.stdMeta, addresses.classTable, "St9type_info");
  pointer(addresses.classMeta + 2 * pointerSize, addresses.stdMeta);
  pointer(addresses.siMeta + 2 * pointerSize, addresses.classMeta);
  pointer(addresses.vmiMeta + 2 * pointerSize, addresses.classMeta);
  type(addresses.base, addresses.classTable, "4Base");
  type(addresses.derived, addresses.siTable, "7Derived");
  pointer(addresses.derived + 2 * pointerSize, addresses.base);
  type(addresses.multiple, addresses.vmiTable, "8Multiple");
  view.setUint32(addresses.multiple + 2 * pointerSize + 4, 1, true);
  pointer(addresses.multiple + 2 * pointerSize + 8, addresses.base);
  // Virtual public base; -3 pointer-sized slots from the vtable address point.
  word(addresses.multiple + 3 * pointerSize + 8, BigInt(-3 * pointerSize) * 256n + 3n);
  table(addresses.table, addresses.base);
  table(addresses.siObjectTable, addresses.derived);
  table(addresses.vmiObjectTable, addresses.multiple);
  word(addresses.vmiObjectTable - 3 * pointerSize, BigInt(2 * pointerSize));
  const image: ItaniumRttiImage = {
    pointerSize, pointers, relocations,
    readOrder: address => address,
    read: async (address, size) => new DataView(bytes.buffer,
      Math.max(0, Math.min(address, bytes.length)),
      address < 0 ? 0 : Math.max(0, Math.min(size, bytes.length - address))),
    isExecutable: address => address >= addresses.code && address < addresses.code + 32
  };
  return { bytes, view, addresses, image, pointer, word, type, table };
};

export const setOrdinaryItaniumSlots = (
  fixture: ReturnType<typeof createItaniumFixture>, slots: "one function" | "first null" | "first data"
): void => {
  const { table, base, code } = fixture.addresses;
  fixture.pointer(table, slots === "one function" ? code : base);
  fixture.pointer(table + fixture.image.pointerSize, base);
  if (slots !== "first null") return;
  fixture.image.pointers.delete(table);
  fixture.image.relocations.delete(table);
  fixture.word(table, 0n);
};

export const createRttiOnlyFixture = (width: 4 | 8) => {
  const fixture = createItaniumFixture(width);
  const { multiple, vmiTable, vmiObjectTable, classTable } = fixture.addresses;
  fixture.type(multiple, vmiTable, "8RttiOnly");
  fixture.type(1024, classTable, "6EmptyA");
  fixture.type(1056, classTable, "6EmptyB");
  fixture.view.setUint32(multiple + 2 * width + 4, 2, true);
  // ABI 2.9.5: two private empty bases, each at offset zero.
  const array = multiple + 2 * width + 8;
  fixture.pointer(array, 1024);
  fixture.word(array + width, 0n);
  fixture.pointer(array + 2 * width, 1056);
  fixture.word(array + 3 * width, 0n);
  fixture.image.pointers.delete(vmiObjectTable - width);
  fixture.image.relocations.delete(vmiObjectTable - width);
  return { ...fixture, falseAddressPoint: array + 3 * width };
};
