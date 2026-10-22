/** Microsoft V3: four-byte header and a payload sized in 16-bit words. */
export const createV3Unwind = (
  payload: readonly number[], control = 0, flags = 0, prologSize = 0
): DataView => {
  const bytes = new Uint8Array(4 + Math.ceil(payload.length / 2) * 2);
  bytes.set([3 | (flags << 3), prologSize, (bytes.length - 4) / 2, control]);
  bytes.set(payload, 4);
  return new DataView(bytes.buffer);
};
