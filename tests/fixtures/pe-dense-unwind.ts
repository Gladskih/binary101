import { MockFile } from "../helpers/mock-file.js";
import { writeRuntimeFunction } from "../helpers/pe-amd64-unwind-fixture.js";
import {
  createMsvcRttiFixtureSections,
  writeMsvcRttiFixtureHeaders
} from "./pe-msvc-rtti-pe.js";

/** Distinct v1 unwind headers with no code slots or language handlers.
 * https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
 */
export const createDenseUnwindPe = (count: number): MockFile => {
  const sections = createMsvcRttiFixtureSections();
  const text = sections[0]!;
  const unwind = sections[1]!;
  unwind.virtualSize = unwind.sizeOfRawData = count * 4;
  const functions = { ...sections[2]!, name: { kind: "inline" as const, value: ".pdata" },
    virtualAddress: unwind.virtualAddress + unwind.virtualSize,
    pointerToRawData: unwind.pointerToRawData + unwind.sizeOfRawData,
    virtualSize: count * 12, sizeOfRawData: count * 12 };
  sections[2] = functions;
  const bytes = new Uint8Array(functions.pointerToRawData + functions.sizeOfRawData);
  const view = new DataView(bytes.buffer);
  writeMsvcRttiFixtureHeaders(bytes, view, 0x8664, 0x20b, sections, 0, true);
  // Fixture PE32+ header: signature at 0x80, optional header after 24 bytes,
  // data directories at +112; exception directory index is 3 (Microsoft PE/COFF).
  const optional = 0x80 + 24;
  view.setUint32(optional + 56, functions.virtualAddress + functions.virtualSize, true);
  view.setUint32(optional + 8, unwind.sizeOfRawData + functions.sizeOfRawData, true);
  view.setUint32(optional + 112 + 3 * 8, functions.virtualAddress, true);
  view.setUint32(optional + 112 + 3 * 8 + 4, functions.sizeOfRawData, true);
  bytes[text.pointerToRawData] = 0xc3;
  for (let index = 0; index < count; index++) {
    bytes[unwind.pointerToRawData + index * 4] = 1;
    writeRuntimeFunction(view, functions.pointerToRawData + index * 12,
      text.virtualAddress, text.virtualAddress + 16, unwind.virtualAddress + index * 4);
  }
  return new MockFile(bytes, "dense-unwind.exe");
};
