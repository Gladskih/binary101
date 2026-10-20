export const decompressSectionZlib = async (
  compressed: Uint8Array,
  expectedSize: number
): Promise<Uint8Array> => {
  if (typeof DecompressionStream !== "function") {
    throw new Error("browser does not provide DecompressionStream");
  }
  const output = new Uint8Array(expectedSize);
  const stream = new Blob([Uint8Array.from(compressed).buffer])
    .stream()
    .pipeThrough(new DecompressionStream("deflate"));
  const streamReader = stream.getReader();
  let offset = 0;
  while (true) {
    const chunk = await streamReader.read();
    if (chunk.done) break;
    if (offset + chunk.value.length > output.length) {
      await streamReader.cancel();
      throw new Error(`output exceeds declared size ${expectedSize}`);
    }
    output.set(chunk.value, offset);
    offset += chunk.value.length;
  }
  if (offset !== output.length) {
    throw new Error(`output size ${offset} does not match declared size ${expectedSize}`);
  }
  return output;
};
