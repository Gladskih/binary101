import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import { readTd32Text } from "./td32-text.js";

// The stored byte length is modulo 256; names are terminated, not limited to 255 bytes.
// https://github.com/project-jedi/jcl/blob/10b92737050d9aaa0af17fe099a737d390b6c80e/jcl/source/windows/JclTD32.pas#L1090
export const readTd32Names = async (reader: LegacyCodeViewReader) => {
  const count = await reader.uint32(0);
  const names: string[] = [];
  let offset = 4;
  const encodings = new Set<string>();
  if (count > Math.floor((reader.size - offset) / 2)) reader.warn("TD32 name count exceeds available bytes.");
  for (let index = 0; index < count && offset < reader.size; index++) {
    try {
      const length = (await reader.view(offset, 1)).getUint8(0);
      const value = await readTd32Text(reader, offset + 1);
      encodings.add(value.encoding);
      if ((value.end - offset - 2) % 256 !== length) reader.warn("TD32 name length disagrees with its terminator.");
      names.push(value.name);
      offset = value.end;
    } catch (error) { reader.warn(String(error)); break; }
  }
  if (names.length !== count) reader.warn("TD32 names table is truncated.");
  if (encodings.has("Windows-1252")) reader.warn("TD32 names contain invalid UTF-8; Windows-1252 is used where the producer code page is unavailable.");
  return { kind: "names" as const, names };
};
