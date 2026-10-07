import type { DwarfCursor } from "./cursor.js";
import { readDwarfFrameInstructions } from "./frame-instructions.js";
import type { DwarfFrameCie, DwarfFrameEncoding } from "./frame-types.js";

const readEncoding = async (cursor: DwarfCursor, version: number,
  targetAddressSize: number): Promise<DwarfFrameEncoding | null> => {
  const addressSize = version === 4 ? await cursor.uint8() : targetAddressSize;
  const segmentSize = version === 4 ? await cursor.uint8() : 0;
  if (cursor.failed) return null;
  if (!addressSize) { cursor.fail("CIE address size is unavailable or zero"); return null; }
  const codeAlignment = await cursor.uleb();
  const dataAlignment = await cursor.sleb();
  const returnRegister = version === 1 ? await cursor.unsigned(1) : await cursor.uleb();
  if (cursor.failed) return null;
  if (!codeAlignment) cursor.notice("CIE code alignment is zero");
  return { addressSize, segmentSize: segmentSize!, codeAlignment: codeAlignment!,
    dataAlignment: dataAlignment!, returnRegister: returnRegister! };
};

// DWARF 5 6.4.1: unknown augmentations invalidate interpretation after the augmentation string.
export const readDwarfFrameCie = async (cursor: DwarfCursor, offset: number, format: 32 | 64,
  byteOrder: "little" | "big", addressSize: number, machine: number,
  issues: string[]): Promise<DwarfFrameCie | null> => {
  const version = await cursor.uint8();
  if (version == null) return null;
  if (![1, 3, 4].includes(version)) { cursor.fail(`Unsupported CIE version ${version}`); return null; }
  const augmentation = await cursor.cstring();
  if (augmentation == null) return null;
  if (augmentation) {
    cursor.notice(`Unknown debug-frame CIE augmentation ${augmentation}`);
    return { offset, version, augmentation, encoding: null, instructions: [] };
  }
  const encoding = await readEncoding(cursor, version, addressSize);
  if (!encoding) return null;
  return { offset, version, augmentation, encoding,
    instructions: await readDwarfFrameInstructions(cursor, encoding.addressSize, format,
      byteOrder, machine, issues) };
};
