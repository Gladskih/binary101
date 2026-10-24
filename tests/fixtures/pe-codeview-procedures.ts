const NARROW_PROCEDURES = new Set([0x0204, 0x0205]);

// CV_PROC symbols and record field positions follow Microsoft's PROCSYM32 structs.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L2760
const putU16 = (view: DataView, offset: number, value: number): void =>
  view.setUint16(offset, value, true);

const putU32 = (view: DataView, offset: number, value: number): void =>
  view.setUint32(offset, value, true);

/** Build source-layout procedure records for the narrow, ST, SZ, and ID variants. */
export const codeViewProcedure = (type: number, name: readonly number[], codeLength = 160,
  debugStart = 16, debugEnd = 144, flags = 0xd5, offset = 0x1234, segment = 9): number[] => {
  const narrow = NARROW_PROCEDURES.has(type);
  const nameOffset = narrow ? 37 : 39;
  const typeOffset = narrow ? 34 : 28;
  const offsetOffset = narrow ? 28 : 32;
  const segmentOffset = narrow ? 32 : 36;
  const flagsOffset = narrow ? 36 : 38;
  const bytes = new Uint8Array(nameOffset + name.length);
  const view = new DataView(bytes.buffer);
  putU16(view, 0, bytes.length - 2);
  putU16(view, 2, type);
  putU32(view, 4, 16);
  putU32(view, 8, 32);
  putU32(view, 12, 48);
  putU32(view, 16, codeLength);
  putU32(view, 20, debugStart);
  putU32(view, 24, debugEnd);
  if (narrow) putU16(view, typeOffset, 0x1234);
  else putU32(view, typeOffset, 0x12345678);
  putU32(view, offsetOffset, offset);
  putU16(view, segmentOffset, segment);
  view.setUint8(flagsOffset, flags);
  bytes.set(name, nameOffset);
  return [...bytes];
};
