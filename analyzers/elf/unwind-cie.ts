import type { DwarfCursor } from "../dwarf/cursor.js";
import type { ElfUnwindCie } from "./unwind-types.js";
import { readElfUnwindPointer } from "./unwind-pointer.js";
import { readElfCfiInstructions } from "./cfi-instructions.js";

// LSB 10.6.1.1 CIE augmentations; DWARF 5 6.4.1 CIE version 4 address sizes.
// https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
const readAugmentation = async (
  cursor: DwarfCursor, cie: ElfUnwindCie, sectionAddress: bigint
): Promise<void> => {
  if (!cie.augmentation) return;
  if (!cie.augmentation.startsWith("z")) {
    cursor.fail(`Unsupported CIE augmentation ${cie.augmentation}`);
    return;
  }
  const size = await cursor.uleb();
  if (size == null) return;
  const end = cursor.position + Number(size);
  if (!Number.isSafeInteger(end) || end > cursor.end) {
    cursor.fail("CIE augmentation is truncated");
    return;
  }
  for (const character of cie.augmentation.slice(1)) {
    await readAugmentationField(cursor, cie, character, sectionAddress);
    if (cursor.failed) return;
  }
  cursor.skip(end - cursor.position);
};

const readAugmentationField = async (
  cursor: DwarfCursor, cie: ElfUnwindCie, character: string, sectionAddress: bigint
): Promise<void> => {
  if (character === "R") cie.fdeEncoding = await cursor.uint8() ?? 0xff;
  else if (character === "L") cie.lsdaEncoding = await cursor.uint8() ?? 0xff;
  else if (character === "P") {
    cie.personality = await readElfUnwindPointer(cursor,
      await cursor.uint8() ?? 0xff, cie.addressSize, sectionAddress);
  } else if (character !== "S") cursor.fail(`Unsupported CIE augmentation ${character}`);
};

const readAddressSize = async (
  cursor: DwarfCursor, version: number, addressSize: number
): Promise<number | null> => {
  const size = version === 4 ? await cursor.uint8() : addressSize;
  const segmentSize = version === 4 ? await cursor.uint8() : 0;
  if ((size !== 4 && size !== 8) || segmentSize !== 0) {
    cursor.fail("Unsupported CIE address or segment size");
    return null;
  }
  return size;
};

export const readElfUnwindCie = async (
  cursor: DwarfCursor, offset: number, addressSize: number, sectionAddress: bigint, machine: number
): Promise<ElfUnwindCie | null> => {
  const version = await cursor.uint8();
  if (version == null || ![1, 3, 4].includes(version)) {
    cursor.fail(`Unsupported CIE version ${version}`);
    return null;
  }
  const augmentation = await cursor.cstring();
  const size = await readAddressSize(cursor, version, addressSize);
  if (size == null) return null;
  const codeAlignment = await cursor.uleb();
  const dataAlignment = await cursor.sleb();
  const returnRegister = version === 1 ? await cursor.unsigned(1) : await cursor.uleb();
  if (cursor.failed) return null;
  if (!codeAlignment) cursor.notice("CIE code alignment is zero");
  const cie: ElfUnwindCie = { offset, version, augmentation: augmentation!, addressSize: size,
    codeAlignment: codeAlignment!, dataAlignment: dataAlignment!, returnRegister: returnRegister!,
    fdeEncoding: 0, lsdaEncoding: 0xff, personality: null, instructions: [] };
  await readAugmentation(cursor, cie, sectionAddress);
  if (cursor.failed) return null;
  cie.instructions = await readElfCfiInstructions(cursor, size, machine);
  return cie;
};
