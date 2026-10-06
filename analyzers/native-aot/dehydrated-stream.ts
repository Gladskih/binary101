import type { NativeAotMetadataSection } from "./format.js";
import type { NativeAotVirtualImage } from "./virtual-image-types.js";
import type { NativeAotHydratedRun } from "./dehydrated-stream-types.js";

// Section size ends at the command stream; its signed relative fixup table follows it.
// This models sparse runs, without allocating the potentially huge hydrated destination.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/DehydratedData.cs
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/nativeaot/Common/src/Internal/Runtime/CompilerHelpers/StartupCodeHelpers.cs
class DehydratedStream {
  readonly #view: DataView;
  #offset = 4;
  #destination: number;
  readonly runs: NativeAotHydratedRun[] = [];

  constructor(readonly image: NativeAotVirtualImage, readonly section: NativeAotMetadataSection,
    bytes: Uint8Array) {
    this.#view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (bytes.byteLength < 4) throw new Error("DehydratedData destination pointer is truncated.");
    this.#destination = section.rva + this.#view.getInt32(0, true);
  }

  #require(size: number): void {
    if (size > this.#view.byteLength - this.#offset) throw new Error("DehydratedData stream is truncated.");
  }

  #command(): { kind: number; payload: number } {
    const command = this.#view.getUint8(this.#offset++);
    const raw = command >>> 3;
    let payload = raw;
    if (raw > 28) {
      this.#require(raw - 28);
      payload = 28;
      for (let index = 0; index < raw - 28; index += 1) {
        payload += this.#view.getUint8(this.#offset++) * 2 ** (index * 8);
      }
    }
    return { kind: command & 7, payload };
  }

  #append(run: NativeAotHydratedRun): void {
    if (!Number.isSafeInteger(run.rva + run.size) || !this.image.isMappedRange(run.rva, run.size)) {
      throw new Error("DehydratedData destination is outside mapped memory.");
    }
    this.runs.push(run);
    this.#destination += run.size;
  }

  async #fixup(index: number): Promise<number> {
    const slot = this.section.rva + this.section.size! + index * 4;
    const view = await this.image.readData(slot, 4, 1);
    if (!view || view.byteLength !== 4) throw new Error("DehydratedData fixup is truncated or unreadable.");
    return slot + view.getInt32(0, true);
  }

  #inlineTarget(): number {
    const target = this.section.rva + this.#offset + this.#view.getInt32(this.#offset, true);
    this.#offset += 4;
    return target;
  }

  async read(): Promise<void> {
    while (this.#offset < this.#view.byteLength) {
      const { kind, payload } = this.#command();
      if (kind === 0) {
        this.#require(payload);
        this.#append({ kind: "copy", rva: this.#destination, size: payload,
          sourceRva: this.section.rva + this.#offset });
        this.#offset += payload;
      } else if (kind === 1) this.#append({ kind: "zero", rva: this.#destination, size: payload });
      else if (kind === 2 || kind === 3) this.#relocation(kind, await this.#fixup(payload));
      else if (kind === 4 || kind === 5) {
        this.#require(payload * 4);
        for (let index = 0; index < payload; index += 1) this.#relocation(kind, this.#inlineTarget());
      } else throw new Error("DehydratedData command has an unknown kind.");
    }
  }

  #relocation(kind: number, target: number): void {
    const relative = kind === 2 || kind === 4;
    this.#append({ kind: relative ? "relative" : "pointer", rva: this.#destination,
      size: relative ? 4 : this.image.pointerSize, target });
  }
}

export const readNativeAotDehydratedRuns = async (image: NativeAotVirtualImage,
  section: NativeAotMetadataSection, bytes: Uint8Array, issues: Set<string>): Promise<NativeAotHydratedRun[]> => {
  let stream: DehydratedStream | undefined;
  try {
    stream = new DehydratedStream(image, section, bytes);
    await stream.read();
  } catch (error) {
    issues.add(error instanceof Error ? error.message : "DehydratedData stream read failed.");
  }
  return stream?.runs ?? [];
};
