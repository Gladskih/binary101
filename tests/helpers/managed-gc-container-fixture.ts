import { createFileRangeReader, type FileRangeReader } from "../../analyzers/file-range-reader.js";
import type { NativeAotMetadata } from "../../analyzers/native-aot/format.js";
import type { RvaToOffset } from "../../analyzers/pe/types.js";
import { GcInfoBitsFixture } from "./gc-info-bits-fixture.js";

export const managedGcContainerFixture = () => {
  const bytes = new Uint8Array(256);
  const view = new DataView(bytes.buffer);
  const mapper: RvaToOffset = Object.assign((rva: number) =>
    rva >= 0 && rva < bytes.length ? rva : null,
  { span: (rva: number) => ({ offset: rva, size: bytes.length - rva }) });
  const metadata: NativeAotMetadata = { status: "confirmed",
    layout: "nativeaot-readytorun-pointer-range-v1", modulePointerRva: 0, headerRva: 0,
    majorVersion: 16, minorVersion: 0, sections: [],
    stackTraceMap: { entries: [{ command: 0, methodRva: 32 }], warnings: [] } };
  // Minimal slim GCInfo v4: code length, no safe points, no register/stack slots.
  const gc = new GcInfoBitsFixture().field(0, 2).unsigned(32, 8)
    .unsigned(0, 2).field(0, 2).bytes();
  return { bytes, view, mapper, metadata, gc,
    reader: () => createFileRangeReader(new File([bytes], "managed.bin"), 0, bytes.length) };
};

export const failManagedGcReadAt = (reader: FileRangeReader, offset: number,
  failure: unknown): FileRangeReader => ({ ...reader, read: async (requested, size) => {
  if (requested === offset) throw failure;
  return reader.read(requested, size);
} });
