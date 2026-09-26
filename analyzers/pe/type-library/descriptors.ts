import type { TypeLibraryReader } from "./reader.js";

// VARENUM in Microsoft's wtypes.h; MSFT_GetTdesc in Wine typelib.c.
// https://learn.microsoft.com/en-us/windows/win32/api/wtypes/ne-wtypes-varenum
export const variantTypeName = (type: number): string =>
  ({ 0: "EMPTY", 1: "NULL", 2: "short", 3: "long", 4: "float", 5: "double",
    6: "CY", 7: "DATE", 8: "BSTR", 9: "IDispatch", 10: "SCODE", 11: "VARIANT_BOOL",
    12: "VARIANT", 13: "IUnknown", 14: "DECIMAL", 16: "char", 17: "unsigned char",
    18: "unsigned short", 19: "unsigned long", 20: "int64", 21: "uint64", 22: "int",
    23: "unsigned int", 24: "void", 25: "HRESULT", 26: "PTR", 27: "SAFEARRAY",
    28: "CARRAY", 29: "USERDEFINED", 30: "LPSTR", 31: "LPWSTR", 64: "FILETIME" } as Record<number, string>)[type] ?? `VARTYPE(${type})`;

interface TypeDescriptorWrapper {
  target: number;
  prefix: string;
  suffix: string;
}

export class MsftTypeDescriptors {
  private readonly nodes = new Map<number, string | TypeDescriptorWrapper>();
  private readonly arrays = new Map<number, string | TypeDescriptorWrapper>();
  private readonly cache = new Map<number, string>();

  constructor(readonly reader: TypeLibraryReader) {}

  read(code: number): string {
    const cached = this.cache.get(code);
    if (cached !== undefined) return cached;
    const wrappers: TypeDescriptorWrapper[] = [];
    const seen = new Set<number>();
    let current = code;
    for (;;) {
      if (seen.has(current)) {
        this.reader.warn("TYPELIB type descriptor contains a cycle.");
        return this.compose(code, `invalid type(${current})`, wrappers);
      }
      seen.add(current);
      const node = this.node(current);
      if (typeof node === "string") return this.compose(code, node, wrappers);
      wrappers.push(node);
      current = node.target;
    }
  }

  private compose(code: number, leaf: string, wrappers: TypeDescriptorWrapper[]): string {
    const value = wrappers.map(wrapper => wrapper.prefix).join("") + leaf +
      wrappers.reverse().map(wrapper => wrapper.suffix).join("");
    this.cache.set(code, value);
    return value;
  }

  private node(code: number): string | TypeDescriptorWrapper {
    const cached = this.nodes.get(code);
    if (cached !== undefined) return cached;
    const node = this.decode(code);
    this.nodes.set(code, node);
    return node;
  }

  private decode(code: number): string | TypeDescriptorWrapper {
    if (code < 0) return variantTypeName(code & 0xfff);
    if (code % 8 !== 0) {
      this.reader.warn("TYPELIB type descriptor is unaligned.");
      return `invalid type(${code})`;
    }
    const start = this.reader.at("TypdescTab", code, 8);
    if (start === null) return `invalid type(${code})`;
    const target = this.reader.view.getInt32(start + 4, true);
    const type = this.reader.view.getUint16(start, true) & 0xfff;
    switch (type) {
      case 26: return { target, prefix: "", suffix: "*" };
      case 27: return { target, prefix: "SAFEARRAY(", suffix: ")" };
      case 28: return this.array(target & 0xffff);
      case 29: return `href(${target})`;
      default: return variantTypeName(type);
    }
  }

  private array(offset: number): string | TypeDescriptorWrapper {
    const cached = this.arrays.get(offset);
    if (cached !== undefined) return cached;
    const array = this.decodeArray(offset);
    this.arrays.set(offset, array);
    return array;
  }

  private decodeArray(offset: number): string | TypeDescriptorWrapper {
    const start = this.reader.at("ArrayDescriptions", offset, 8);
    if (start === null) return "invalid array";
    const dimensions = this.reader.view.getUint16(start + 4, true);
    if (dimensions === 0 ||
      this.reader.at("ArrayDescriptions", offset + 8, dimensions * 8) === null) {
      this.reader.warn("TYPELIB array dimensions are invalid or truncated.");
      return "invalid array";
    }
    return { target: this.reader.view.getInt32(start, true), prefix: "",
      suffix: Array.from({ length: dimensions }, (_, index) => {
        const bound = start + 8 + index * 8;
        const lower = this.reader.view.getInt32(bound + 4, true);
        return `[${lower}..${lower + this.reader.view.getUint32(bound, true) - 1}]`;
      }).join("") };
  }
}
