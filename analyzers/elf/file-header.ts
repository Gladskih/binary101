import { ELF_CLASS, ELF_DATA, ELF_TYPE, ELF_MACHINE, decodeOption } from "./constants.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import type { ElfFileHeaderRecord } from "./binary-layout-types.js";
import type { ElfHeader, ElfIdent, ElfParseResult } from "./types.js";

const ELF_MAGIC = 0x7f454c46;
const emptyElfHeader = (): ElfHeader => ({
  type: 0,
  typeName: null,
  machine: 0,
  machineName: null,
  entry: 0n,
  phoff: 0n,
  shoff: 0n,
  flags: 0,
  ehsize: 0,
  phentsize: 0,
  phnum: 0,
  shentsize: 0,
  shnum: 0,
  shstrndx: 0
});
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
    machineName: decodeOption(header.machine, ELF_MACHINE) || null
  };
}

export const readElfFileHeader = async (file: File): Promise<ElfParseResult | null> => {
  const view = new DataView(await file.slice(0, Math.min(file.size, 4096)).arrayBuffer());
  // sizeof(Elf32_Ehdr); a complete ELF identification alone is not a parseable file.
  if (view.byteLength < 0x34 || view.getUint32(0, false) !== ELF_MAGIC) return null;
  const issues: string[] = [];
  const ident = parseIdent(view, issues);
  const result: ElfParseResult = { ident, header: emptyElfHeader(), sections: [], programHeaders: [],
    issues, is64: ident.classByte === 2, littleEndian: ident.dataByte === 1, fileSize: file.size };
  if (!isSupportedElfIdent(ident)) return result;
  const layout = selectElfBinaryLayout(result);
  const record = layout.readHeader(view);
  if (!record) {
    issues.push(`ELF${result.is64 ? "64" : "32"} header is truncated: ` +
      `expected at least ${layout.headerSize} bytes, got ${view.byteLength}.`);
    return result;
  }
  result.header = describeElfHeader(record, issues);
  return result;
};

export const isSupportedElfIdent = (ident: ElfIdent): boolean =>
  [1, 2].includes(ident.classByte) && [1, 2].includes(ident.dataByte);
