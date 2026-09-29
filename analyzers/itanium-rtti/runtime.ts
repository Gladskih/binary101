import type { ItaniumRecords } from "./records.js";
import type { ItaniumClassKind, ItaniumRttiImage, ItaniumVtable } from "./types.js";

// GCC's runtime inheritance graph: libstdc++-v3/libsupc++/cxxabi.h.
// https://github.com/gcc-mirror/gcc/blob/master/libstdc++-v3/libsupc++/cxxabi.h
const CLASS_NAME = "N10__cxxabiv117__class_type_infoE";
const SI_NAME = "N10__cxxabiv120__si_class_type_infoE";
const VMI_NAME = "N10__cxxabiv121__vmi_class_type_infoE";

const runtimeTable = async (
  image: ItaniumRttiImage, records: ItaniumRecords, address: number, name: string
): Promise<ItaniumVtable | null> => {
  const table = await records.runtimeTable(address);
  if (!table || await records.name(table.typeAddress) !== name) return null;
  return (await image.read(table.typeAddress, 3 * image.pointerSize)).byteLength ===
    3 * image.pointerSize ? table : null;
};

const hasStdBase = async (
  image: ItaniumRttiImage, records: ItaniumRecords, classMeta: number, classTable: number
): Promise<boolean> => {
  const stdMeta = image.pointers.get(classMeta + 2 * image.pointerSize);
  if (stdMeta == null || await records.name(stdMeta) !== "St9type_info") return false;
  return image.pointers.get(stdMeta) === classTable;
};

const closedRuntime = async (
  image: ItaniumRttiImage, records: ItaniumRecords, classTable: number
): Promise<number | null> => {
  const table = await runtimeTable(image, records, classTable, CLASS_NAME);
  if (!table) return null;
  const classMeta = table.typeAddress;
  const siTable = image.pointers.get(classMeta);
  if (siTable == null || siTable === classTable) return null;
  const single = await runtimeTable(image, records, siTable, SI_NAME);
  if (!single) return null;
  if (image.pointers.get(single.typeAddress) !== siTable) return null;
  if (image.pointers.get(single.typeAddress + 2 * image.pointerSize) !== classMeta) return null;
  return await hasStdBase(image, records, classMeta, classTable) ? siTable : null;
};

const hasVmiBase = async (
  image: ItaniumRttiImage, records: ItaniumRecords,
  kinds: Map<number, ItaniumClassKind>, address: number
): Promise<boolean> => {
  const table = await runtimeTable(image, records, address, VMI_NAME);
  if (!table) return false;
  const single = image.pointers.get(table.typeAddress);
  if (single == null || kinds.get(single) !== "si") return false;
  const singleTable = (await records.runtimeTable(single))!;
  return image.pointers.get(table.typeAddress + 2 * image.pointerSize) ===
    image.pointers.get(singleTable.typeAddress + 2 * image.pointerSize);
};

export const findItaniumRuntime = async (
  image: ItaniumRttiImage, records: ItaniumRecords
): Promise<Map<number, ItaniumClassKind>> => {
  const kinds = new Map<number, ItaniumClassKind>();
  const candidates: number[] = [];
  for (const address of await records.prepare()) {
    const table = await records.table(address);
    if (!table) continue;
    const name = await records.name(table.typeAddress);
    if (name === VMI_NAME) candidates.push(address);
    if (name !== CLASS_NAME) continue;
    const single = await closedRuntime(image, records, address);
    if (single == null) continue;
    kinds.set(address, "class");
    kinds.set(single, "si");
  }
  for (const address of candidates) {
    if (!await hasVmiBase(image, records, kinds, address)) continue;
    kinds.set(address, "vmi");
  }
  return kinds;
};
