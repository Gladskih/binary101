import { readGuid } from "./reader.js";

// SLTG uses packed, often unaligned records; reads are always bounded to a single block.
export class SltgReader {
  readonly view: DataView;
  decoder = new TextDecoder("windows-1252");
  references = new Map<number, number>();
  helpStrings: { decode(stream: Uint8Array): string | null } | null = null;
  private readonly names = new Map<number, string | null>();
  private readonly helpStreams = new Map<number, string | null>();

  constructor(
    readonly data: Uint8Array, readonly issues: string[],
    private readonly reportedIssues = new Set(issues)
  ) {
    this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  }

  range(offset: number, size: number): boolean {
    if (offset >= 0 && size >= 0 && Number.isSafeInteger(offset) &&
      Number.isSafeInteger(size) && offset <= this.data.length && size <= this.data.length - offset) {
      return true;
    }
    this.warn("TYPELIB SLTG record is truncated or points outside its block.");
    return false;
  }

  warn(message: string): void {
    if (this.reportedIssues.has(message)) return;
    this.reportedIssues.add(message);
    this.issues.push(message);
  }

  slice(start: number, end = this.data.length): SltgReader {
    const reader = new SltgReader(this.range(start, end - start)
      ? this.data.subarray(start, end) : new Uint8Array(), this.issues, this.reportedIssues);
    reader.decoder = this.decoder;
    reader.helpStrings = this.helpStrings;
    reader.references = this.references;
    return reader;
  }

  word(offset: number): number | null {
    return this.range(offset, 2) ? this.view.getUint16(offset, true) : null;
  }

  string(offset: number): { text: string | null; next: number } | null {
    const length = this.word(offset);
    if (length === null) return null;
    if (length === 0xffff) return { text: null, next: offset + 2 };
    if (!this.range(offset + 2, length)) return null;
    return { text: this.decoder.decode(this.data.subarray(offset + 2, offset + 2 + length)),
      next: offset + 2 + length };
  }

  stringEnd(offset: number): number | null {
    const length = this.word(offset);
    if (length === null) return null;
    if (length === 0xffff) return offset + 2;
    return this.range(offset + 2, length) ? offset + 2 + length : null;
  }

  name(offset: number): string | null {
    const cached = this.names.get(offset);
    if (cached !== undefined) return cached;
    if (!this.range(offset, 1)) return null;
    const end = this.data.indexOf(0, offset);
    if (end < 0) {
      this.warn("TYPELIB SLTG name is not terminated.");
      this.names.set(offset, null);
      return null;
    }
    const result = this.decoder.decode(this.data.subarray(offset, end));
    this.names.set(offset, result);
    return result;
  }

  guid(offset: number): string | null {
    return this.range(offset, 16) ? readGuid(this.view, offset) : null;
  }

  help(offset: number): string | null {
    if (offset === 0xffff) return null;
    const cached = this.helpStreams.get(offset);
    if (cached !== undefined) return cached;
    if (!this.range(offset, 1) || !this.helpStrings) return null;
    const text = this.helpStrings.decode(this.data.subarray(offset));
    this.helpStreams.set(offset, text);
    return text;
  }
}
