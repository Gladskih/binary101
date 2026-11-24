import { COFF_FILE_CHARACTERISTICS, COFF_SECTION_CHARACTERISTICS } from "../../coff/layout.js";
import { IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386 } from "../../coff/machine.js";
import type { FileRangeReader } from "../../file-range-reader.js";
import { getPeArchitecturePageSize } from "../layout/page-size.js";
import { parseOptionalHeaderTail32, parseOptionalHeaderTail64 } from "../optional-header/layouts.js";
import { PE32_OPTIONAL_HEADER_MAGIC, PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "../optional-header/magic.js";
import { mappedRvaSpan } from "../rva-mapping.js";
import type { PeWindowsCore } from "../types.js";
import { computeEntrySection } from "./entry.js";

export type PeRecoveredEntrypoint = { rva: number; imageBase: bigint; flatRvaLimit?: number };

// Both layouts have a DWORD AddressOfEntryPoint at +16 and SizeOfHeaders at +60.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only
const ENTRY_POINT_FIELD_OFFSET = 16;
const SIZE_OF_HEADERS_FIELD_END = 64;

const readUndeclaredEntrypointFields = async (reader: FileRangeReader, core: PeWindowsCore) => {
  if (core.coff.SizeOfOptionalHeader >= ENTRY_POINT_FIELD_OFFSET + Uint32Array.BYTES_PER_ELEMENT ||
      SIZE_OF_HEADERS_FIELD_END > reader.size - core.optOff) return null;
  const view = await reader.read(core.optOff, SIZE_OF_HEADERS_FIELD_END);
  if (view.byteLength < SIZE_OF_HEADERS_FIELD_END) return null;
  const rva = view.getUint32(ENTRY_POINT_FIELD_OFFSET, true);
  const readTail = core.opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC
    ? parseOptionalHeaderTail64 : parseOptionalHeaderTail32;
  // The common PE32/PE32+ fields through BaseOfCode end at +24.
  const { ImageBase, SectionAlignment, FileAlignment, SizeOfImage, SizeOfHeaders } = readTail(view, 24);
  return rva > 0 && rva < SizeOfImage
    ? { rva, ImageBase, SectionAlignment, FileAlignment, SizeOfImage, SizeOfHeaders } : null;
};

const supportsEntrypointRecovery = ({ coff, opt, sections }: PeWindowsCore): boolean =>
  (coff.Characteristics & COFF_FILE_CHARACTERISTICS.EXECUTABLE_IMAGE) !== 0 &&
  sections.length === coff.NumberOfSections &&
  ((coff.Machine === IMAGE_FILE_MACHINE_I386 && opt.Magic === PE32_OPTIONAL_HEADER_MAGIC) ||
   (coff.Machine === IMAGE_FILE_MACHINE_AMD64 && opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC));

// Low-alignment images map file bytes at identical RVAs when the two alignments agree.
// https://github.com/wine-mirror/wine/blob/wine-10.0/dlls/ntdll/unix/virtual.c
const isFlatImageAlignment = (sectionAlignment: number, fileAlignment: number, machine: number) =>
  sectionAlignment === fileAlignment &&
  sectionAlignment > 0 && (sectionAlignment & (sectionAlignment - 1)) === 0 &&
  sectionAlignment < getPeArchitecturePageSize(machine);

export async function recoverPeEntrypoint(
  reader: FileRangeReader, core: PeWindowsCore
): Promise<PeRecoveredEntrypoint | undefined> {
  if (!supportsEntrypointRecovery(core)) return;
  const { coff, optOff, sections } = core;
  const fields = await readUndeclaredEntrypointFields(reader, core);
  if (!fields) return;
  const { rva, ImageBase: imageBase } = fields;
  const section = await computeEntrySection({ AddressOfEntryPoint: rva }, sections);
  if (section) {
    if ((sections[section.index]!.characteristics & COFF_SECTION_CHARACTERISTICS.MEM_EXECUTE) &&
        mappedRvaSpan(core.rvaToOff, rva, 1, reader.size)) return { rva, imageBase };
    return;
  }
  // Limit the flat fallback to sectionless images to honor section permissions and mappings.
  const flatRvaLimit = Math.min(reader.size, fields.SizeOfImage);
  if (sections.length || rva >= flatRvaLimit || fields.SizeOfHeaders > flatRvaLimit ||
      fields.SizeOfHeaders < optOff + coff.SizeOfOptionalHeader ||
      !isFlatImageAlignment(fields.SectionAlignment, fields.FileAlignment, coff.Machine)) return;
  return { rva, imageBase, flatRvaLimit };
}
