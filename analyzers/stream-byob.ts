// Chromium may collect a BYOB reader while only its pending read's continuation
// references it. Retain each pending reader until settlement, including rejection
// and cancellation. Remove this workaround when crbug.com/574627778 is fixed in
// supported browsers. Track promises separately for overlapping reads on one reader.
const pendingReads = new Map<
  Promise<ReadableStreamReadResult<Uint8Array<ArrayBuffer>>>, ReadableStreamBYOBReader
>();

export const readByobChunk = async (
  reader: ReadableStreamBYOBReader,
  destination: Uint8Array<ArrayBuffer>,
  options?: ReadableStreamBYOBReaderReadOptions
): Promise<ReadableStreamReadResult<Uint8Array<ArrayBuffer>>> => {
  const pending = reader.read(destination, options);
  pendingReads.set(pending, reader);
  try { return await pending; }
  finally { pendingReads.delete(pending); }
};
