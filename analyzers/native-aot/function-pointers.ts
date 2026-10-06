import type { NativeAotDehydratedData } from "./dehydrated-data.js";

// FatFunctionPointerOffset=2 on non-Wasm targets. The untagged descriptor contains the
// canonical method pointer followed by an instantiation argument (data, never a seed).
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/System.Private.CoreLib/src/Internal/Runtime/CompilerServices/FunctionPointerOps.cs
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/FatFunctionPointerNode.cs
export class NativeAotFunctionPointers {
  readonly #cache = new Map<number, Promise<number | null>>();
  constructor(readonly data: NativeAotDehydratedData, readonly issues: Set<string>) {}

  resolve(address: number): Promise<number | null> {
    const cached = this.#cache.get(address);
    if (cached) return cached;
    const result = this.#read(address);
    this.#cache.set(address, result);
    return result;
  }

  async #read(address: number): Promise<number | null> {
    try {
      if (!Number.isSafeInteger(address) || address < 0) throw new Error("Invalid NativeAOT function pointer.");
      if (address % 4 >= 2) return await this.#descriptor(address - 2);
      if (!this.data.image.isExecutableAddress(address)) {
        throw new Error("NativeAOT function pointer target is not file-backed executable code.");
      }
      return address;
    } catch (error) {
      this.issues.add(error instanceof Error ? error.message : "NativeAOT function pointer read failed.");
      return null;
    }
  }

  async #descriptor(address: number): Promise<number | null> {
    const image = this.data.image;
    if (address % image.pointerSize || !image.isMappedRange(address, image.pointerSize * 2)) {
      throw new Error("NativeAOT generic method descriptor is unaligned or out of bounds.");
    }
    const method = await this.data.pointer(address);
    const context = await this.data.pointer(address + image.pointerSize);
    if (method === null || !image.isExecutableAddress(method) ||
      context === null || !image.isMappedRange(context, 1)) {
      throw new Error("NativeAOT generic method descriptor has an invalid code or context pointer.");
    }
    return method;
  }
}
