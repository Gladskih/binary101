import type { DwarfCursor } from "./cursor.js";
import { dwarfSectionContributions } from "./section-contributions.js";
import { readDwarfFrameCie } from "./frame-cie.js";
import { readDwarfFrameInstructions } from "./frame-instructions.js";
import { evaluateDwarfCfi } from "./cfi-state.js";
import type { DwarfFrames, DwarfFrameCie, DwarfFrameFde } from "./frame-types.js";
import type { DwarfSectionSource } from "./types.js";

type PendingFrame = { offset: number; format: 32 | 64; cursor: DwarfCursor; cieOffset: bigint };

const validateFdeRange = (cursor: DwarfCursor, offset: number, addressSize: number,
  start: bigint, range: bigint): void => {
  if (start + range > 1n << BigInt(addressSize * 8)) cursor.notice("FDE range exceeds the target address width");
  if ((cursor.end - offset) % addressSize) cursor.notice("FDE record is not aligned to its address size");
};

const readFde = async (cursor: DwarfCursor, offset: number, cie: DwarfFrameCie,
  format: 32 | 64, byteOrder: "little" | "big", targetAddressSize: number, machine: number,
  issues: string[]): Promise<DwarfFrameFde | null> => {
  const addressSize = cie.encoding?.addressSize ?? targetAddressSize;
  if (!addressSize) { cursor.fail("FDE address size is unavailable"); return null; }
  const segment = cie.encoding?.segmentSize ? await cursor.unsigned(cie.encoding.segmentSize) : null;
  const start = await cursor.unsigned(addressSize);
  const range = await cursor.unsigned(addressSize);
  if (cursor.failed) return null;
  validateFdeRange(cursor, offset, addressSize, start!, range!);
  return { offset, cieOffset: cie.offset, start: start!, segment, range: range!,
    instructions: cie.encoding ? await readDwarfFrameInstructions(cursor, addressSize,
      format, byteOrder, machine, issues) : [] };
};

export const readDwarfFrames = async (source: DwarfSectionSource, byteOrder: "little" | "big",
  addressSize: number, machine: number, issues: string[]): Promise<DwarfFrames> => {
  const frames: DwarfFrames = { cies: [], fdes: [] };
  const pending: PendingFrame[] = [];
  for await (const { offset, format, cursor } of dwarfSectionContributions(source, byteOrder, issues)) {
    const identifier = await cursor.unsigned(format / 8);
    if (identifier == null) continue;
    if (identifier !== (1n << BigInt(format)) - 1n) {
      pending.push({ offset, format, cursor, cieOffset: identifier });
      continue;
    }
    const cie = await readDwarfFrameCie(cursor, offset, format, byteOrder, addressSize, machine, issues);
    if (!cie) continue;
    if (cie.encoding && (cursor.end - offset) % cie.encoding.addressSize) {
      cursor.notice("CIE record is not aligned to its address size");
    }
    frames.cies.push(cie);
  }
  await decodePendingFrames(frames, pending, byteOrder, addressSize, machine, issues);
  return frames;
};

const decodePendingFrames = async (frames: DwarfFrames, pending: PendingFrame[],
  byteOrder: "little" | "big", addressSize: number, machine: number, issues: string[]): Promise<void> => {
  const cies = new Map(frames.cies.map(cie => [BigInt(cie.offset), cie]));
  for (const { offset, format, cursor, cieOffset } of pending) {
    const cie = cies.get(cieOffset);
    if (!cie) { cursor.notice("FDE references an invalid CIE boundary"); continue; }
    const fde = await readFde(cursor, offset, cie, format, byteOrder, addressSize, machine, issues);
    if (!fde) continue;
    frames.fdes.push(fde);
    if (!cie.encoding) continue;
    for (const issue of evaluateDwarfCfi({ ...cie.encoding, instructions: cie.instructions }, fde).issues) {
      cursor.notice(issue);
    }
  }
};
