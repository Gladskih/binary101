import { ZSTDDecoder } from "zstddec";

type ZstdExports = WebAssembly.Exports & {
  malloc: (size: number) => number;
  free: (pointer: number) => void;
  ZSTD_decompress: (output: number, capacity: number, input: number, size: number) => number;
  ZSTD_isError: (code: number) => number;
};

// zstddec 0.3.1 omits ZSTD_isError in decode(). Check the native result before
// its heap slice, and retain its decoder and embedded WASM (no network service).
// https://github.com/donmccurdy/zstddec/blob/v0.3.1/src/zstddec.ts
// https://github.com/facebook/zstd/blob/v1.5.7/lib/zstd.h
class CheckedZstdDecoder extends ZSTDDecoder {
  private failure: string | null = null;
  private allocations = new Set<number>();
  private release: (pointer: number) => void = () => {};

  override _init = (result: WebAssembly.WebAssemblyInstantiatedSource): void => {
    const exports = result.instance.exports as ZstdExports;
    this.release = exports.free;
    // The upstream initialization hook only reads instance.exports. Its public
    // type requires an Instance; the facade preserves every native export.
    super._init({ ...result, instance: { exports: { ...exports,
      malloc: (size: number) => this.allocate(exports, size),
      free: (pointer: number) => {
        exports.free(pointer);
        this.allocations.delete(pointer);
      },
      ZSTD_decompress: (output: number, capacity: number, input: number, size: number) => {
        const code = exports.ZSTD_decompress(output, capacity, input, size);
        if (!exports.ZSTD_isError(code)) return code;
        this.failure = `Zstandard decoder error ${code >>> 0}`;
        return 0;
      }
    } } as unknown as WebAssembly.Instance });
  };

  private allocate(exports: ZstdExports, size: number): number {
    const pointer = exports.malloc(size);
    if (!pointer) throw new Error("Zstandard decoder could not allocate memory");
    this.allocations.add(pointer);
    return pointer;
  }

  override decode(bytes: Uint8Array, expectedSize = 0): Uint8Array {
    this.failure = null;
    try {
      // Passing zero invokes upstream size discovery. A one-byte capacity
      // permits valid empty frames while keeping the ELF size authoritative.
      const output = super.decode(bytes, Math.max(1, expectedSize));
      if (this.failure) throw new Error(this.failure);
      if (output.length !== expectedSize) {
        throw new Error(`output size ${output.length} does not match declared size ${expectedSize}`);
      }
      return output;
    } finally {
      for (const pointer of this.allocations) this.release(pointer);
      this.allocations.clear();
    }
  }
}

let decoder: Promise<CheckedZstdDecoder> | null = null;

const initializeDecoder = async (): Promise<CheckedZstdDecoder> => {
  const initialized = new CheckedZstdDecoder();
  await initialized.init();
  return initialized;
};

export const decompressDwarfZstd = async (bytes: Uint8Array, expectedSize: number): Promise<Uint8Array> => {
  // The bundled decoder uses wasm32 pointers and size_t, not JS safe integers.
  if (!Number.isSafeInteger(expectedSize) || expectedSize < 0 || expectedSize >= 2 ** 32 || bytes.length >= 2 ** 32) {
    throw new Error("section size is outside the Zstandard decoder's wasm32 address space");
  }
  decoder ??= initializeDecoder();
  return (await decoder).decode(bytes, expectedSize);
};
