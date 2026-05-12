"use strict";

export const createBareMidiSignatureBytes = (): Uint8Array => {
  const bytes = new Uint8Array(64);
  // Standard MIDI Files 1.0 starts with the ASCII "MThd" header chunk ID.
  // https://midi.org/standard-midi-files-specification
  bytes[0] = 0x4d;
  bytes[1] = 0x54;
  bytes[2] = 0x68;
  bytes[3] = 0x64;
  return bytes;
};

export const createMinimalMidiFileBytes = (): Uint8Array => {
  const bytes = new Uint8Array(26);
  const view = new DataView(bytes.buffer);
  // SMF fixture: MThd length 6, format 0, one MTrk chunk, and an End of Track meta event.
  // https://midi.org/standard-midi-files-specification
  view.setUint32(0, 0x4d546864, false);
  view.setUint32(4, 6, false);
  view.setUint16(8, 0, false);
  view.setUint16(10, 1, false);
  view.setUint16(12, 96, false);
  view.setUint32(14, 0x4d54726b, false);
  view.setUint32(18, 4, false);
  bytes.set([0x00, 0xff, 0x2f, 0x00], 22);
  return bytes;
};
