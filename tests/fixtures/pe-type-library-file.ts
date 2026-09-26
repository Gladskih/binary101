import { createPeResourcePreviewFile } from "./pe-resource-preview-file.js";
import { createMsftLibrary } from "./type-library.js";
import { createSltgLibrary } from "./type-library-sltg.js";
import { createResourceDirectoryFixture } from "../helpers/pe-resource-fixture.js";
import { MockFile } from "../helpers/mock-file.js";

export const createPeTypeLibraryFile = (): MockFile => {
  const bytes = createPeResourcePreviewFile().data;
  // Reuse the valid PE32+ envelope (.rsrc at file 0x400, RVA 0x2000).
  const resources = createResourceDirectoryFixture(4096);
  const msft = createMsftLibrary();
  const sltg = createSltgLibrary();
  resources.writeDirectory(0, 1, 0);
  resources.writeDirectoryEntry(16, 0x800000b0, 0x80000018);
  resources.writeUtf16Label(176, "TYPELIB");
  resources.writeDirectory(24, 0, 2);
  resources.writeDirectoryEntry(40, 1, 0x80000038);
  resources.writeDirectoryEntry(48, 2, 0x80000050);
  resources.writeDirectory(56, 0, 1);
  resources.writeDirectoryEntry(72, 1033, 104);
  resources.writeDirectory(80, 0, 1);
  resources.writeDirectoryEntry(96, 1033, 120);
  resources.writeDataEntry(104, 0x2100, msft.length, 0);
  resources.writeDataEntry(120, 0x2998, sltg.length, 0);
  resources.bytes.set(msft, 256);
  resources.bytes.set(sltg, 2456);
  bytes.fill(0, 1024);
  bytes.set(resources.bytes, 1024);
  return new MockFile(bytes, "type-libraries.exe");
};
