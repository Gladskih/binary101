import { createFileRangeReader, type FileRangeReader } from "../../analyzers/file-range-reader.js";
import type { NativeAotMetadata } from "../../analyzers/native-aot/format.js";
import type { RvaToOffset } from "../../analyzers/pe/types.js";
import { GcInfoBitsFixture } from "./gc-info-bits-fixture.js";

// Synthetic PE/ELF placements. AMD64 RuntimeFunction has three DWORDs (12 bytes); the
// remaining addresses only keep ranges apart. https://learn.microsoft.com/windows/win32/debug/pe-format#the-pdata-section
export const managedGcContainerFixture = () => {
  const layout = { fileSize: 256, methodRva: 32, nativeOnlyMethodRva: 40,
    exceptionDirectoryRva: 128, rootUnwindRva: 64, rootGcInfoRva: 69,
    alignedGcInfoRva: 72, nextUnwindRva: 96, runtimeFunctionBytes: 12,
    codeLength: 32 } as const;
  const bytes = new Uint8Array(layout.fileSize);
  const view = new DataView(bytes.buffer);
  const mapper: RvaToOffset = Object.assign((rva: number) =>
    rva >= 0 && rva < bytes.length ? rva : null,
  { span: (rva: number) => ({ offset: rva, size: bytes.length - rva }) });
  const metadata: NativeAotMetadata = { status: "confirmed",
    layout: "nativeaot-readytorun-pointer-range-v1", modulePointerRva: 0, headerRva: 0,
    majorVersion: 16, minorVersion: 0, sections: [],
    stackTraceMap: { entries: [{ command: 0, methodRva: layout.methodRva }], warnings: [] } };
  // v4 starts with two format bits then an 8-bit-group code length; 32 bytes gives
  // the synthetic method a valid, nonzero extent. See dotnet/runtime v10 encoder:
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/gcinfo/gcinfoencoder.cpp
  const gc = new GcInfoBitsFixture().field(0, 2).unsigned(layout.codeLength, 8)
    .unsigned(0, 2).field(0, 2).bytes();
  return { bytes, view, mapper, metadata, gc, layout,
    reader: () => createFileRangeReader(new File([bytes], "managed.bin"), 0, bytes.length) };
};

export const failManagedGcReadAt = (reader: FileRangeReader, offset: number,
  failure: unknown): FileRangeReader => ({ ...reader, read: async (requested, size) => {
  if (requested === offset) throw failure;
  return reader.read(requested, size);
} });
