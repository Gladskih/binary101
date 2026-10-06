import { createHeadersOnlyPeWithAlignedImageSize } from "./minimal-pe-headers.js";

export const createSanitizerPeFile = (): Uint8Array<ArrayBuffer> => {
  const bytes = new Uint8Array(1024);
  bytes.set(createHeadersOnlyPeWithAlignedImageSize());
  const view = new DataView(bytes.buffer);
  const optional = view.getUint32(0x3c, true) + 24;
  // PE32 header fields / import descriptor / IMAGE_THUNK_DATA32:
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-directory-table
  // All incidental fixture RVAs fit in SizeOfHeaders, so RVA=file offset.
  view.setUint32(optional + 60, bytes.length, true);
  view.setUint32(optional + 92, 16, true);
  view.setUint32(optional + 104, 512, true); // IMPORT directory slot, after EXPORT.
  view.setUint32(optional + 108, 40, true); // Descriptor plus terminating zero descriptor.
  view.setUint32(512, 576, true); // OriginalFirstThunk.
  view.setUint32(524, 640, true); // Name.
  view.setUint32(528, 608, true); // FirstThunk.
  view.setUint32(576, 704, true);
  view.setUint32(580, 736, true);
  view.setUint32(608, 704, true);
  view.setUint32(612, 736, true);
  bytes.set(new TextEncoder().encode("clang_rt.asan_dynamic-i386.dll\0"), 640);
  // Import-by-name strings follow a two-byte hint.
  bytes.set(new TextEncoder().encode("__asan_init\0"), 706);
  bytes.set(new TextEncoder().encode("__asan_report_load4\0"), 738);
  return bytes;
};
