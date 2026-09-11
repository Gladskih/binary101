import type { DwarfCursor } from "../dwarf/cursor.js";
import type { ArmEhabiDescriptor } from "./arm-ehabi-types.js";
import { armPrel31 } from "./arm-ehabi-program.js";

const readLandingPad = async (cursor: DwarfCursor, address: bigint,
  descriptor: ArmEhabiDescriptor): Promise<void> => {
  const place = address + BigInt(cursor.position);
  const word = await cursor.uint32();
  if (word == null) return;
  descriptor.landingPad = armPrel31(word, place);
  if (descriptor.kind === "catch") descriptor.referenceCatch = (word & 0x80000000) !== 0;
  else if (word & 0x80000000) cursor.notice("Reserved high bit in EHABI landing pad PREL31");
};

const readSpecification = async (cursor: DwarfCursor, address: bigint,
  descriptor: ArmEhabiDescriptor): Promise<void> => {
  const word = await cursor.uint32();
  if (word == null) return;
  const count = word & 0x7fffffff;
  if (count > 100000 || count > Math.floor((cursor.end - cursor.position) / 4)) {
    cursor.fail("EHABI exception specification exceeds bounds or type limit");
    return;
  }
  for (let index = 0; index < count; index++) {
    const type = await cursor.uint32();
    if (type == null) return;
    descriptor.types.push(type);
  }
  if (word & 0x80000000) await readLandingPad(cursor, address, descriptor);
};

const descriptorReaders = [
  { kind: "cleanup", read: readLandingPad },
  { kind: "catch", read: async (cursor: DwarfCursor, address: bigint, descriptor: ArmEhabiDescriptor) => {
    await readLandingPad(cursor, address, descriptor);
    const type = await cursor.uint32();
    if (type != null) descriptor.types.push(type);
  } },
  { kind: "exception specification", read: readSpecification }
] as const;

const readScope = async (cursor: DwarfCursor, personality: number) => {
  const integer = personality === 2 ? () => cursor.uint32() : () => cursor.uint16();
  const length = await integer();
  if (length == null || (length === 0 && personality === 2)) return null;
  const start = await integer();
  if (start == null || (length === 0 && start === 0)) return null;
  if (!(length & 0xfffffffe)) { cursor.fail("EHABI scope has zero length"); return null; }
  return { length, start };
};

// EHABI32 §9.2: short/long scopes and cleanup, catch, exception-specification descriptors.
// Type words retain their R_ARM_TARGET2 encoding, whose interpretation depends on the platform.
export const readArmEhabiDescriptors = async (
  cursor: DwarfCursor, personality: number, address: bigint
): Promise<ArmEhabiDescriptor[]> => {
  const descriptors: ArmEhabiDescriptor[] = [];
  while (!cursor.failed && descriptors.length < 100000) {
    const scope = await readScope(cursor, personality);
    if (!scope) return descriptors;
    const decoder = descriptorReaders[(scope.length & 1) | ((scope.start & 1) << 1)];
    if (!decoder) { cursor.fail("Reserved EHABI scope kind"); return descriptors; }
    const descriptor: ArmEhabiDescriptor = { kind: decoder.kind,
      start: scope.start - (scope.start & 1), length: scope.length - (scope.length & 1), types: [] };
    await decoder.read(cursor, address, descriptor);
    if (!cursor.failed) descriptors.push(descriptor);
  }
  if (!cursor.failed) cursor.notice("EHABI descriptor limit reached");
  return descriptors;
};
