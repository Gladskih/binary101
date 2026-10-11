// Real large PE inputs exceeded Set's per-address capacity. A 64 KiB address page
// uses 8 KiB of bits, allocated only when an address is added. X86 instruction starts
// are byte-granular, including overlapping decodes; mark starts, not instruction spans.
// Mutation stays inside each traversal's private page store, with no fixed page budget.
const createBytePageSet = <PageId>() => {
  const pages = new Map<PageId, Uint8Array>();
  return {
    has: (pageId: PageId, offset: number): boolean =>
      ((pages.get(pageId)?.[offset >>> 3] ?? 0) & (1 << (offset & 7))) !== 0,
    add: (pageId: PageId, offset: number): void => {
      let page = pages.get(pageId);
      if (!page) {
        page = new Uint8Array(8192);
        pages.set(pageId, page);
      }
      page[offset >>> 3]! |= 1 << (offset & 7);
    },
    delete: (pageId: PageId, offset: number): void => {
      const page = pages.get(pageId);
      if (page) page[offset >>> 3]! &= ~(1 << (offset & 7));
    }
  };
};

const isRva = (address: number): boolean =>
  Number.isInteger(address) && address >= 0 && address <= 0xffff_ffff;

export const createX86RvaSet = () => {
  const pages = createBytePageSet<number>();
  return {
    has: (address: number): boolean =>
      isRva(address) && pages.has(address >>> 16, address & 0xffff),
    add: (address: number): void => {
      if (isRva(address)) pages.add(address >>> 16, address & 0xffff);
    },
    delete: (address: number): void => {
      if (isRva(address)) pages.delete(address >>> 16, address & 0xffff);
    }
  };
};

const isVaddr = (address: bigint): boolean => address >= 0n && address <= 0xffffffffffffffffn;

export const createX86VaddrSet = () => {
  const pages = createBytePageSet<bigint>();
  return {
    has: (address: bigint): boolean =>
      isVaddr(address) && pages.has(address >> 16n, Number(address & 0xffffn)),
    add: (address: bigint): void => {
      if (isVaddr(address)) pages.add(address >> 16n, Number(address & 0xffffn));
    },
    delete: (address: bigint): void => {
      if (isVaddr(address)) pages.delete(address >> 16n, Number(address & 0xffffn));
    }
  };
};
