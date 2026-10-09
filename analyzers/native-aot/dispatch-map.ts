import type { NativeAotFunctionReferences } from "./function-references.js";

export interface NativeAotDispatchEntry {
  kind: "standard" | "default" | "static" | "default static";
  interfaceIndex: number;
  interfaceMethodSlot: number;
  implementationSlot: number;
  contextSource?: number;
}
export interface NativeAotDispatchMap {
  rva: number;
  counts: number[];
  entries: NativeAotDispatchEntry[];
}

export class NativeAotDispatchMaps {
  readonly #cache = new Map<number, Promise<NativeAotDispatchMap | null>>();
  constructor(readonly references: NativeAotFunctionReferences) {}

  read(rva: number): Promise<NativeAotDispatchMap | null> {
    let result = this.#cache.get(rva);
    if (!result) { result = this.#read(rva); this.#cache.set(rva, result); }
    return result;
  }

  async #ushort(address: number): Promise<number> {
    const value = await this.references.data.unsigned(address, 2);
    if (value === null) throw new Error("NativeAOT dispatch map is truncated or unreadable.");
    return value;
  }

  async #entry(address: number, kind: NativeAotDispatchEntry["kind"]): Promise<NativeAotDispatchEntry> {
    const interfaceIndex = await this.#ushort(address);
    const interfaceMethodSlot = await this.#ushort(address + 2);
    const implementationSlot = await this.#ushort(address + 4);
    return { kind, interfaceIndex, interfaceMethodSlot, implementationSlot,
      ...(kind.includes("static") ? { contextSource: await this.#ushort(address + 6) } : {}) };
  }

  async #entries(map: NativeAotDispatchMap): Promise<void> {
    let address = map.rva + 8;
    const kinds = ["standard", "default", "static", "default static"] as const;
    for (const [group, kind] of kinds.entries()) {
      for (let index = 0; index < map.counts[group]!; index++) {
        const size = group < 2 ? 6 : 8;
        this.#validateRange(address, size);
        map.entries.push(await this.#entry(address, kind));
        address += size;
      }
    }
  }

  #validateRange(rva: number, size: number): void {
    if (rva % 2 || this.references.image.isExecutableAddress(rva) ||
      !this.references.image.isMappedRange(rva, size)) {
      throw new Error("NativeAOT dispatch map has an invalid mapped range or alignment.");
    }
  }

  async #read(rva: number): Promise<NativeAotDispatchMap | null> {
    let map: NativeAotDispatchMap | null = null;
    try {
      // DispatchMap and InterfaceDispatchMapNode: four ushort counts, then 6/6/8/8-byte groups.
      // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Common/src/Internal/Runtime/MethodTable.cs
      this.#validateRange(rva, 8);
      const counts: number[] = [];
      for (let index = 0; index < 4; index++) counts.push(await this.#ushort(rva + index * 2));
      map = { rva, counts, entries: [] };
      await this.#entries(map);
    } catch (error) {
      this.references.issues.add(error instanceof Error ? error.message : "NativeAOT dispatch map read failed.");
    }
    return map;
  }
}
