import type { NativeAotFunctionReferences } from "./function-references.js";
import type { NativeAotRuntimeType } from "./runtime-type-map.js";
import type { NativeAotMetadata } from "./format.js";
import { NativeAotDispatchMaps, type NativeAotDispatchMap } from "./dispatch-map.js";

export interface NativeAotSealedSlot {
  slot: number;
  targetRva: number | null;
  requiresInstantiatingThunk: boolean;
}
export interface NativeAotRuntimeTail {
  finalizerRva: number | null;
  dispatchMap: NativeAotDispatchMap | null;
  sealedSlots: NativeAotSealedSlot[];
}

export class NativeAotRuntimeTails {
  readonly #dispatch: NativeAotDispatchMaps;
  constructor(readonly references: NativeAotFunctionReferences,
    readonly version?: Pick<NativeAotMetadata, "majorVersion" | "minorVersion">) {
    this.#dispatch = new NativeAotDispatchMaps(references);
  }

  #knownLayout(type: NativeAotRuntimeType): boolean {
    // EETypeFlags: HasDispatchMap | HasFinalizerFlag | HasSealedVTableEntriesFlag.
    // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/MethodTable.Constants.cs
    if (!(type.flags & 0x00540000)) return false;
    // ModuleHeaders.cs identifies .NET 9 (10.1) and .NET 10 (16.0).
    // .NET 8 also had CppCodegen absolute tails and optional fields, without a header discriminator.
    // https://github.com/dotnet/runtime/blob/v9.0.0/src/coreclr/tools/Common/Internal/Runtime/ModuleHeaders.cs
    if ((this.version?.majorVersion === 10 && this.version.minorVersion === 1) ||
      (this.version?.majorVersion === 16 && this.version.minorVersion === 0)) return true;
    this.references.issues.add("MethodTable tail layout is not verified for this NativeAOT header version.");
    return false;
  }

  async #code(address: number): Promise<number | null> {
    const target = await this.references.data.relative(address);
    if (target === null) return null;
    if (this.references.image.isExecutableAddress(target)) return target;
    this.references.issues.add("MethodTable finalizer target is not file-backed executable code.");
    return null;
  }

  async #sealedSlot(address: number, slot: number, type: NativeAotRuntimeType): Promise<NativeAotSealedSlot> {
    const target = await this.references.data.relative(address + slot * 4);
    // SealedVTableNode adds flag 2 to shared DynamicInterfaceCastable implementation pointers.
    // Other class methods can naturally have bit 2 set and must retain their exact address.
    // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/SealedVTableNode.cs
    const requiresInstantiatingThunk = (type.flags & 0x7c000000) === 0x54000000 &&
      target !== null && (target & 2) !== 0;
    const rva = target === null ? null : target - (requiresInstantiatingThunk ? 2 : 0);
    if (rva === null) return { slot, targetRva: null, requiresInstantiatingThunk };
    if (this.references.image.isExecutableAddress(rva)) return { slot, targetRva: rva, requiresInstantiatingThunk };
    this.references.issues.add("MethodTable sealed slot target is not file-backed executable code.");
    return { slot, targetRva: null, requiresInstantiatingThunk };
  }

  #sealedIndices(type: NativeAotRuntimeType, map: NativeAotDispatchMap | null): number[] {
    const indices = new Set<number>();
    for (const entry of map?.entries ?? []) {
      if (entry.interfaceIndex >= type.numInterfaces ||
        (entry.contextSource ?? 0) > type.numInterfaces + 1) {
        this.references.issues.add("NativeAOT dispatch map interface or context index is outside the type interface map.");
        continue;
      }
      // RuntimeConstants.SpecialDispatchMapSlot reserves the last two ushort values.
      // DispatchResolve subtracts NumVtableSlots only for real sealed implementations.
      // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Runtime.Base/src/System/Runtime/DispatchResolve.cs
      if (entry.implementationSlot >= type.numVtableSlots && entry.implementationSlot < 0xfffe) {
        indices.add(entry.implementationSlot - type.numVtableSlots);
      }
    }
    return [...indices];
  }

  async #sealed(type: NativeAotRuntimeType, map: NativeAotDispatchMap | null,
    address: number): Promise<NativeAotSealedSlot[]> {
    const indices = this.#sealedIndices(type, map);
    if (!(type.flags & 0x00400000)) {
      if (indices.length) this.references.issues.add("Dispatch map references sealed slots without a sealed vtable.");
      return [];
    }
    const target = await this.references.data.relative(address);
    if (target === null) return [];
    if (target % 4 || this.references.image.isExecutableAddress(target) ||
      !this.references.image.isMappedRange(target, 4)) {
      this.references.issues.add("MethodTable sealed vtable has an invalid mapped range or alignment.");
      return [];
    }
    const slots: NativeAotSealedSlot[] = [];
    for (const index of indices) slots.push(await this.#sealedSlot(target, index, type));
    return slots;
  }

  async read(type: NativeAotRuntimeType): Promise<NativeAotRuntimeTail | null> {
    if (!this.#knownLayout(type)) return null;
    if (type.flags & 0x00080000) {
      this.references.issues.add("Dynamic MethodTable tails cannot describe statically emitted NativeAOT code.");
      return null;
    }
    // GetFieldOffset: fixed header, absolute vtable/interface slots, type-manager and writable relptr32.
    // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Common/src/Internal/Runtime/MethodTable.cs
    let address = type.rva + 16 + this.references.image.pointerSize *
      (1 + type.numVtableSlots + type.numInterfaces) + 8;
    let dispatchMap: NativeAotDispatchMap | null = null;
    if (type.flags & 0x00040000) {
      const target = await this.references.data.relative(address);
      if (target !== null) dispatchMap = await this.#dispatch.read(target);
      address += 4;
    }
    const finalizerRva = type.flags & 0x00100000 ? await this.#code(address) : null;
    if (type.flags & 0x00100000) address += 4;
    return { finalizerRva, dispatchMap, sealedSlots: await this.#sealed(type, dispatchMap, address) };
  }
}
