import { ELF_MACHINE_OPTIONS } from "./legacy-machine-types.js";
import { ELF_CLASS, ELF_DATA, ELF_TYPE, decodeOption } from "./constants.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import { readElfHeaderPrefix } from "./file-header-record.js";
import type { ElfFileHeaderRecord } from "./binary-layout-types.js";
import type { ElfHeader, ElfIdent, ElfReport } from "./types.js";

const ELF_MAGIC = 0x7f454c46;
function parseIdent(dv: DataView, issues: string[]): ElfIdent {
  const cls = dv.getUint8(4);
  const data = dv.getUint8(5);
  const version = dv.getUint8(6);
  const osabi = dv.getUint8(7);
  const abiVersion = dv.getUint8(8);
  const className = decodeOption(cls, ELF_CLASS) || "Unknown";
  const dataName = decodeOption(data, ELF_DATA) || "Unknown";
  // gABI 2.2: only ELFCLASS32/64 and ELFDATA2LSB/MSB define supported layouts.
  // https://gabi.xinuos.com/elf/02-eheader.html
  if (cls !== 1 && cls !== 2) issues.push(`Unsupported ELF class ${cls}; layout is unknown.`);
  if (data !== 1 && data !== 2) {
    issues.push(`Unsupported ELF data encoding ${data}; byte order is unknown.`);
  }
  if (version !== 1) issues.push(`Unexpected ELF version ${version}.`);
  return { classByte: cls, className, dataByte: data, dataName, osabi, abiVersion };
}
function describeElfHeader(record: ElfFileHeaderRecord, issues: string[]): ElfHeader {
  const { version, ...header } = record;
  if (version !== 1) issues.push(`Unexpected ELF header version ${version}.`);
  return {
    ...header,
    typeName: decodeOption(header.type, ELF_TYPE) || null,
    machineName: decodeOption(header.machine, ELF_MACHINE_OPTIONS) || null
  };
}

export const readElfFileHeader = async (file: File): Promise<ElfReport | null> => {
  // gABI 2: 16-byte e_ident and a maximum fixed ELF header size of 64 bytes.
  const view = new DataView(await file.slice(0, 64).arrayBuffer());
  if (view.byteLength < 16 || view.getUint32(0, false) !== ELF_MAGIC) return null;
  const issues: string[] = [];
  const ident = parseIdent(view, issues);
  if (!isSupportedElfIdent(ident)) return { incompleteHeader: true, ident, header: {}, issues };
  const is64 = ident.classByte === 2;
  const littleEndian = ident.dataByte === 1;
  const layout = selectElfBinaryLayout({ is64, littleEndian });
  const record = layout.readHeader(view);
  if (record) {
    return { ident, header: describeElfHeader(record, issues), sections: [], programHeaders: [],
      issues, is64, littleEndian, fileSize: file.size };
  }
  issues.push(`ELF${is64 ? "64" : "32"} header is truncated: ` +
    `expected at least ${layout.headerSize} bytes, got ${view.byteLength}.`);
  const { version, ...header } = readElfHeaderPrefix(view, layout.byteOrder, is64 ? 8 : 4);
  if (version !== undefined && version !== 1) issues.push(`Unexpected ELF header version ${version}.`);
  return { incompleteHeader: true, ident, header, issues };
};

export const isSupportedElfIdent = (ident: ElfIdent): boolean =>
  [1, 2].includes(ident.classByte) && [1, 2].includes(ident.dataByte);
