import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";
import { readTd32TypeField } from "./td32-type-field-record.js";
import type { Td32TypeField } from "./td32-type-member-types.js";

// LF_PAD's low nibble gives its total byte extent, including the marker.
// TIS CodeView, Field List; map2dbg uses the same count for TD32 lists.
// https://www.x-ways.net/winhex/kb/ff/PE_EXE.pdf#page=88
const skipPadding = async (reader: LegacyCodeViewReader, offset: number, marker: number): Promise<number> => {
  const count = marker & 15;
  if (!count) throw new Error("TD32 LF_PAD0 cannot advance the field list.");
  await reader.view(offset, count);
  return offset + count;
};

/** Preserve complete fields and stop at the first unrecognized or truncated leaf. */
export const readTd32TypeFields = async (reader: LegacyCodeViewReader): Promise<Td32TypeField[]> => {
  const fields: Td32TypeField[] = [];
  let offset = 0;
  while (offset < reader.size) {
    try {
      const marker = (await reader.view(offset, 1)).getUint8(0);
      if (marker >= 0xf0) { offset = await skipPadding(reader, offset, marker); continue; }
      const decoded = await readTd32TypeField(reader.subsection(offset, reader.size - offset));
      fields.push(decoded.field);
      offset += decoded.end;
    } catch (error) { reader.warn(`TD32 field list: ${String(error)}`); break; }
  }
  return fields;
};
