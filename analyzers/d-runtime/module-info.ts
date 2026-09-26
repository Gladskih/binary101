import type { DModuleInfo, DRuntimeImage } from "./types.js";
import { readDExact, readDModuleName, readDPointer, readDPointerArray } from "./fields.js";
import { D_MODULE_FLAGS, D_MODULE_INFO_LAYOUT } from "./layout.js";

// Modern druntime metadata only: betterC emits no ModuleInfo. ClassInfo pointers are
// retained as references; this record does not describe all functions like Go pclntab.
const readCallbacks = async (
  image: DRuntimeImage, address: bigint, flags: number
): Promise<DModuleInfo["callbacks"] | null> => {
  const fields = D_MODULE_INFO_LAYOUT.callbacks.filter(field => (flags & field.flag) !== 0);
  if (!fields.length) return [];
  const view = await readDExact(image, address, fields.length * image.pointerSize);
  if (!view) return null;
  const callbacks = fields.map((field, index) => ({
    kind: field.kind, address: readDPointer(image, view, index * image.pointerSize)
  }));
  return callbacks.every(callback => callback.address !== 0n && image.isExecutable(callback.address))
    ? callbacks : null;
};

const readReferences = (
  image: DRuntimeImage, address: bigint, flags: number, flag: number
): Promise<bigint[] | null> =>
  (flags & flag) !== 0 ? readDPointerArray(image, address,
    pointer => isMappedReference(image, pointer)) : Promise.resolve([]);

const referenceSize = (flags: number, flag: number, count: number, pointerSize: number): bigint =>
  BigInt((flags & flag) !== 0 ? (count + 1) * pointerSize : 0);

const isMappedReference = (image: DRuntimeImage, address: bigint): boolean =>
  address !== 0n && address % BigInt(image.pointerSize) === 0n &&
  image.isMapped(address, D_MODULE_INFO_LAYOUT.headerBytes);

const readModuleHeader = async (image: DRuntimeImage, address: bigint)
  : Promise<Pick<DModuleInfo, "flags" | "index"> | null> => {
  if (address < 0n || address % BigInt(image.pointerSize) !== 0n) return null;
  const header = await readDExact(image, address, D_MODULE_INFO_LAYOUT.headerBytes);
  if (!header) return null;
  const flags = header.getUint32(D_MODULE_INFO_LAYOUT.flagsOffset, image.littleEndian);
  // Only known MI flags; MIname is required for conservative modern-layout detection.
  return (flags & ~D_MODULE_INFO_LAYOUT.knownFlagMask) === 0 && (flags & D_MODULE_FLAGS.name) !== 0
    ? { flags, index: header.getUint32(D_MODULE_INFO_LAYOUT.indexOffset, image.littleEndian) } : null;
};

export const parseDModuleInfo = async (
  image: DRuntimeImage, address: bigint
): Promise<DModuleInfo | null> => {
  const header = await readModuleHeader(image, address);
  if (!header) return null;
  const flags = header.flags;
  const callbacksAddress = address + BigInt(D_MODULE_INFO_LAYOUT.headerBytes);
  const callbacks = await readCallbacks(image, callbacksAddress, flags);
  if (!callbacks) return null;
  const importsAddress = callbacksAddress + BigInt(callbacks.length * image.pointerSize);
  const importedModules = await readReferences(image, importsAddress, flags,
    D_MODULE_FLAGS.importedModules);
  if (!importedModules) return null;
  const classesAddress = importsAddress +
    referenceSize(flags, D_MODULE_FLAGS.importedModules, importedModules.length, image.pointerSize);
  const localClasses = await readReferences(image, classesAddress, flags, D_MODULE_FLAGS.localClasses);
  if (!localClasses) return null;
  const name = await readDModuleName(image, classesAddress +
    referenceSize(flags, D_MODULE_FLAGS.localClasses, localClasses.length, image.pointerSize));
  return name ? {
    address, ...header, name,
    callbacks, importedModules, localClasses
  } : null;
};
