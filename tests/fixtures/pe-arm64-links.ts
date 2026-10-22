import { MockFile } from "../helpers/mock-file.js";

export const createArm64LinkChain = (links: number) => {
  const count = links + 1;
  const directory = { name: "EXCEPTION", rva: 64, size: count * 8 };
  const code = Math.ceil((directory.rva + directory.size + 64) / 16) * 16;
  const bytes = new Uint8Array(code + count * 4);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < count; index++) {
    view.setUint32(directory.rva + index * 8, code + index * 4, true);
    // Microsoft ARM64 .pdata: Flag=3 links to a parent row; Flag=1 packs length*4.
    // https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling#pdata-record-links
    view.setUint32(directory.rva + index * 8 + 4,
      index < links ? (directory.rva + (index + 1) * 8) | 3 : 5, true);
  }
  return { file: new MockFile(bytes), directory, code };
};
