import { createLegacyCodeView, legacyU16, legacyU32 } from "./pe-legacy-codeview.js";

// JCL TD32 structures: https://github.com/project-jedi/jcl/blob/10b92737050d9aaa0af17fe099a737d390b6c80e/jcl/source/windows/JclTD32.pas
export const td32Names = (names = ["unit.pas", "Worker", "source.pas"]): Uint8Array =>
  Uint8Array.from([...legacyU32(names.length), ...names.flatMap(name => {
    const bytes = new TextEncoder().encode(name);
    return [bytes.length % 256, ...bytes, 0];
  })]);

export const td32Module = (nameIndex = 1): Uint8Array => Uint8Array.from([
  ...legacyU16(0), ...legacyU16(0), ...legacyU16(1), 84, 68,
  ...legacyU32(nameIndex), ...legacyU32(123), ...new Array<number>(12).fill(0),
  ...legacyU16(1), ...legacyU16(1), ...legacyU32(16), ...legacyU32(32)
]);

export const td32Symbol = (type = 0x205, nameIndex = 2, nameOffset = 40): number[] => {
  const bytes = new Uint8Array(nameOffset + 4);
  bytes.set(legacyU16(bytes.length - 2));
  bytes.set(legacyU16(type), 2);
  bytes.set(legacyU32(nameIndex), nameOffset);
  return [...bytes];
};

export const td32Source = (): Uint8Array => Uint8Array.from([
  ...legacyU16(1), ...legacyU16(1), ...legacyU32(20), ...legacyU32(16), ...legacyU32(48), ...legacyU16(1), 0, 0,
  ...legacyU16(1), ...legacyU32(3), ...legacyU32(38), ...legacyU32(16), ...legacyU32(48),
  ...legacyU16(1), ...legacyU16(2), ...legacyU32(16), ...legacyU32(24), ...legacyU16(7), ...legacyU16(9)
]);

export const td32MultiSource = (): Uint8Array => Uint8Array.from([
  ...legacyU16(1), ...legacyU16(2), ...legacyU32(28),
  ...legacyU32(16), ...legacyU32(24), ...legacyU32(32), ...legacyU32(40), ...legacyU16(1), ...legacyU16(2),
  ...legacyU16(2), ...legacyU32(3), ...legacyU32(60), ...legacyU32(76),
  ...legacyU32(16), ...legacyU32(24), ...legacyU32(32), ...legacyU32(40), 0, 0,
  ...legacyU16(1), ...legacyU16(2), ...legacyU32(16), ...legacyU32(24), ...legacyU16(7), ...legacyU16(9),
  ...legacyU16(2), ...legacyU16(2), ...legacyU32(32), ...legacyU32(40), ...legacyU16(11), ...legacyU16(13)
]);

export const createTd32 = (entries = [
  { type: 0x130, module: 0xffff, data: td32Names() },
  { type: 0x120, module: 1, data: td32Module() },
  { type: 0x125, module: 1, data: Uint8Array.from([...legacyU32(1), ...td32Symbol()]) },
  { type: 0x127, module: 1, data: td32Source() }
], signature = "FB09"): Uint8Array => {
  const core = createLegacyCodeView(entries, signature);
  return Uint8Array.from([...core, ...new TextEncoder().encode(signature), ...legacyU32(core.length + 8)]);
};
