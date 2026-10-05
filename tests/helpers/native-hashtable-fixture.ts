export const createNativeHashtableFixture = (payloads: Uint8Array[], width = 1): Uint8Array => {
  // One bucket; its directory includes start and end. Every reference is a five-byte
  // signed NativeFormat integer to keep fixture offsets independent of payload sizes.
  // NativeHashtable.cs / NativeReader.DecodeSigned, dotnet/runtime v10.0.0.
  const directoryEnd = 1 + width * 2;
  const bucketEnd = directoryEnd + payloads.length * 6;
  const bytes = new Uint8Array(bucketEnd + payloads.reduce((sum, item) => sum + item.length, 0));
  const view = new DataView(bytes.buffer);
  bytes[0] = width === 1 ? 0 : width === 2 ? 1 : 2;
  const writeIndex = (offset: number, value: number): void => {
    if (width === 1) view.setUint8(offset, value);
    else if (width === 2) view.setUint16(offset, value, true);
    else view.setUint32(offset, value, true);
  };
  writeIndex(1, directoryEnd - 1);
  writeIndex(1 + width, bucketEnd - 1);
  let destination = bucketEnd;
  payloads.forEach((payload, index) => {
    const entry = directoryEnd + index * 6;
    bytes[entry] = index;
    bytes[entry + 1] = 15;
    view.setInt32(entry + 2, destination - entry - 1, true);
    bytes.set(payload, destination);
    destination += payload.length;
  });
  return bytes;
};
