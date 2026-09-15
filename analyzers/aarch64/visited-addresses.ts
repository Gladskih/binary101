// A64 is four-byte aligned (AAELF64, Mapping symbols).
// https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst
// One bit per instruction: a 64 KiB code page needs 2 KiB, unlike a bigint Set entry per word.
// Allocate pages on demand without imposing a fixed instruction or page budget.
export const createAarch64VisitedTracker = () => {
  const pages = new Map<bigint, Uint8Array>();
  return (address: bigint): "new" | "seen" | "invalid" => {
    if (address < 0n || address > 0xffffffffffffffffn || address % 4n !== 0n) return "invalid";
    const pageId = address >> 16n;
    let page = pages.get(pageId);
    if (!page) {
      page = new Uint8Array(2048);
      pages.set(pageId, page);
    }
    const bit = Number(address & 0xffffn) >>> 2;
    const mask = 1 << (bit & 7);
    if ((page[bit >>> 3]! & mask) !== 0) return "seen";
    page[bit >>> 3]! |= mask;
    return "new";
  };
};
