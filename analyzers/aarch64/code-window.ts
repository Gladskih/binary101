// Cache only the bounded segment supplied by the PE/ELF reader. Sequential instructions
// use synchronous views instead of re-entering the async file reader for every four bytes.
export const createAarch64CodeWindow = (readCode: (address: bigint) => Promise<Uint8Array>) => {
  let start = -1n;
  let bytes: Uint8Array = new Uint8Array();
  return (address: bigint): Uint8Array | Promise<Uint8Array> => {
    const offset = address - start;
    if (offset >= 0n && offset < BigInt(bytes.length)) {
      return bytes.subarray(Number(offset), Number(offset) + 4);
    }
    return readCode(address).then(block => {
      start = address;
      bytes = block;
      return block.subarray(0, 4);
    });
  };
};
