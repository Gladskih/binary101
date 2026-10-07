import type { DwarfCursor } from "./cursor.js";
import type { DwarfNameIndexHeader } from "./name-index-types.js";

const validVersion = (cursor: DwarfCursor, version: number | null, padding: number | null): boolean => {
  if (version === 5 && padding === 0) return true;
  cursor.fail("Invalid name index version or padding");
  return false;
};

export const readDwarfNameIndexHeader = async (
  cursor: DwarfCursor, format: 32 | 64
): Promise<DwarfNameIndexHeader | null> => {
  const version = await cursor.uint16();
  const padding = await cursor.uint16();
  if (cursor.failed) return null;
  if (!validVersion(cursor, version, padding)) return null;
  const fields: number[] = [];
  // DWARF 5 6.1.1.4.1: seven uword counts/sizes following version/padding.
  for (let index = 0; index < 7; index += 1) {
    const value = await cursor.uint32();
    if (value == null) return null;
    fields.push(value);
  }
  const [compileUnitCount, localTypeUnitCount, foreignTypeUnitCount, bucketCount,
    nameCount, abbreviationSize, augmentationSize] = fields as [number, number, number, number, number, number, number];
  const required = BigInt(compileUnitCount + localTypeUnitCount + nameCount * 2) * BigInt(format / 8) +
    BigInt(foreignTypeUnitCount) * 8n + BigInt(bucketCount + (bucketCount ? nameCount : 0)) * 4n +
    BigInt(abbreviationSize) + BigInt(augmentationSize);
  if (required > BigInt(cursor.end - cursor.position) || augmentationSize % 4) {
    cursor.fail("Name index arrays exceed their contribution or augmentation size is not aligned");
    return null;
  }
  const bytes = await cursor.bytes(augmentationSize);
  if (!bytes) return null;
  return { compileUnitCount, localTypeUnitCount, foreignTypeUnitCount, bucketCount,
    nameCount, abbreviationSize, augmentation: new TextDecoder().decode(bytes).replace(/\0+$/, "") };
};
