import type { ResourceTypeLibrarySegmentPreview } from "../resources/preview/types.js";
import type { TypeLibraryCustomData, TypeLibraryValue } from "./types.js";

// All offsets below follow Wine MSFT_NameIntro / MSFT_GuidEntry / MSFT_pSeg.
// https://github.com/wine-mirror/wine/blob/master/dlls/oleaut32/typelib.h
export class TypeLibraryReader {
  readonly view: DataView;
  readonly names = new Map<number, string>();
  readonly strings = new Map<number, string>();
  readonly guids = new Map<number, string>();
  readonly values = new Map<number, TypeLibraryValue | null>();
  readonly customData = new Map<number, TypeLibraryCustomData[]>();
  readonly decoder: TextDecoder;
  private readonly reportedIssues: Set<string>;

  constructor(
    readonly data: Uint8Array,
    readonly segments: ResourceTypeLibrarySegmentPreview[],
    readonly issues: string[]
  ) {
    this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    this.reportedIssues = new Set(issues);
    // TYPELIB strings use the Windows ANSI codepage, not UTF-8 (Wine CP_ACP).
    // LCID is evidence for the encoding, but not an explicit codepage declaration.
    this.decoder = createTypeLibraryDecoder(data.length >= 16 ? this.view.getUint32(12, true) : 0);
  }

  warn(message: string): void {
    if (this.reportedIssues.has(message)) return;
    this.reportedIssues.add(message);
    this.issues.push(message);
  }

  range(offset: number, size: number, end = this.data.length): boolean {
    return Number.isSafeInteger(offset) && Number.isSafeInteger(size) && offset >= 0 &&
      size >= 0 && end <= this.data.length && offset <= end && size <= end - offset;
  }

  segment(name: string): ResourceTypeLibrarySegmentPreview | null {
    const segment = this.segments.find(entry => entry.name === name);
    return segment && this.range(segment.offset, segment.length) ? segment : null;
  }

  at(name: string, offset: number, size: number): number | null {
    const segment = this.segment(name);
    if (segment && this.range(offset, size, segment.length)) return segment.offset + offset;
    this.warn(`TYPELIB ${name} reference ${offset} is outside the segment.`);
    return null;
  }

  lookup(table: Map<number, string>, offset: number, label: string): string | null {
    if (offset === -1) return null;
    const value = table.get(offset);
    if (value === undefined) this.warn(`TYPELIB ${label} reference ${offset} is invalid.`);
    return value ?? null;
  }

  text(offset: number, size: number): string {
    if (!this.range(offset, size)) {
      this.warn("TYPELIB text range is outside the resource.");
      return "";
    }
    return this.decoder.decode(this.data.subarray(offset, offset + size));
  }
}

export const readGuid = (view: DataView, offset: number): string | null => {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > view.byteLength - 16) return null;
  const hex = (value: number, width: number): string => value.toString(16).padStart(width, "0");
  return `${hex(view.getUint32(offset, true), 8)}-` +
    `${hex(view.getUint16(offset + 4, true), 4)}-${hex(view.getUint16(offset + 6, true), 4)}-` +
    Array.from({ length: 8 }, (_, index) => hex(view.getUint8(offset + 8 + index), 2))
      .join("").replace(/^(.{4})/, "$1-");
};

export const createTypeLibraryDecoder = (lcid: number): TextDecoder => {
  // Serbian/Bosnian Cyrillic share primary language 26 with Latin-script locales.
  // Windows CultureInfo.TextInfo.ANSICodePage reports 1251 for these LCIDs.
  // https://learn.microsoft.com/en-us/dotnet/api/system.globalization.textinfo.ansicodepage
  if ([0xc1a, 0x1c1a, 0x201a, 0x281a, 0x301a, 0x641a, 0x6c1a].includes(lcid & 0xffff)) {
    return new TextDecoder("windows-1251");
  }
  // Chinese sublanguages 1/3/5 use Big5; other Chinese locales use GBK.
  // https://learn.microsoft.com/en-us/windows/win32/intl/language-identifier-constants-and-strings
  if ((lcid & 0x3ff) === 4) return new TextDecoder([1, 3, 5].includes((lcid >>> 10) & 63) ? "big5" : "gbk");
  return new TextDecoder(({
    17: "shift_jis", 18: "euc-kr", 25: "windows-1251", 8: "windows-1253", 31: "windows-1254",
    13: "windows-1255", 1: "windows-1256", 30: "windows-874", 42: "windows-1258",
    5: "windows-1250", 14: "windows-1250", 21: "windows-1250", 24: "windows-1250",
    26: "windows-1250", 27: "windows-1250", 36: "windows-1250",
    37: "windows-1257", 38: "windows-1257", 39: "windows-1257"
  } as Record<number, string>)[lcid & 0x3ff] ?? "windows-1252");
};

const readTextTable = (reader: TypeLibraryReader, name: "NameTab" | "StringTab"): void => {
  const segment = reader.segment(name);
  if (!segment) return;
  const prefix = name === "NameTab" ? 12 : 2;
  const table = name === "NameTab" ? reader.names : reader.strings;
  for (let offset = 0; offset < segment.length;) {
    const start = segment.offset + offset;
    if (!reader.range(offset, prefix, segment.length)) {
      reader.warn(`TYPELIB ${name} record is truncated.`);
      break;
    }
    const length = name === "NameTab"
      ? reader.view.getUint8(start + 8) : reader.view.getUint16(start, true);
    const size = Math.max(name === "NameTab" ? 12 : 8, Math.ceil((prefix + length) / 4) * 4);
    if (!reader.range(offset, size, segment.length)) {
      reader.warn(`TYPELIB ${name} text is truncated.`);
      break;
    }
    table.set(offset, reader.text(start + prefix, length));
    offset += size;
  }
};

export const readMsftTables = (reader: TypeLibraryReader): void => {
  readTextTable(reader, "NameTab");
  readTextTable(reader, "StringTab");
  const segment = reader.segment("GuidTab");
  if (!segment) return;
  if (segment.length % 24) reader.warn("TYPELIB GUID table has a truncated record.");
  for (let offset = 0; offset + 24 <= segment.length; offset += 24) {
    reader.guids.set(offset, readGuid(reader.view, segment.offset + offset)!);
  }
};
