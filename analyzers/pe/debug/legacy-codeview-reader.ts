export class LegacyCodeViewReader {
  private warnedAnsi = false;
  private ansiRoot: LegacyCodeViewReader = this;
  constructor(readonly size: number,
    private readonly readRange: (offset: number, size: number) => Promise<DataView>,
    readonly warn: (message: string) => void) {}

  async view(offset: number, size: number): Promise<DataView> {
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size) ||
      offset < 0 || size < 0 || size > this.size - offset) throw new Error("CodeView subsection bounds exceeded.");
    const view = await this.readRange(offset, size);
    if (view.byteLength !== size) throw new Error("CodeView subsection is truncated.");
    return view;
  }

  async uint16(offset: number): Promise<number> { return (await this.view(offset, 2)).getUint16(0, true); }
  async uint32(offset: number): Promise<number> { return (await this.view(offset, 4)).getUint32(0, true); }

  subsection(offset: number, size: number): LegacyCodeViewReader {
    const reader = new LegacyCodeViewReader(size, (relative, count) => this.view(offset + relative, count), this.warn);
    reader.ansiRoot = this.ansiRoot;
    return reader;
  }

  // CV4 names are byte-counted ANSI strings, not UTF-8. No code page is recorded.
  // https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/cvdump/cvdump.cpp#L394
  async pascal(offset: number): Promise<{ name: string; end: number }> {
    const size = (await this.view(offset, 1)).getUint8(0);
    return { name: await this.ansiBytes(offset + 1, size), end: offset + size + 1 };
  }

  async ansiBytes(offset: number, size: number): Promise<string> {
    const view = await this.view(offset, size);
    return this.decodeAnsi(new Uint8Array(view.buffer, view.byteOffset, view.byteLength));
  }

  private decodeAnsi(bytes: Uint8Array): string {
    if (!this.ansiRoot.warnedAnsi && bytes.some(byte => byte >= 128)) {
      this.ansiRoot.warnedAnsi = true;
      this.warn("Legacy CodeView ANSI code page is not recorded; non-ASCII text is shown as Windows-1252.");
    }
    return new TextDecoder("windows-1252", { ignoreBOM: true }).decode(bytes);
  }

  async ansi(offset: number): Promise<{ name: string; end: number }> {
    let name = "";
    for (let cursor = offset; cursor < this.size; cursor += 256) {
      const view = await this.view(cursor, Math.min(256, this.size - cursor));
      const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
      const end = bytes.indexOf(0);
      if (end >= 0) return { name: name + this.decodeAnsi(bytes.subarray(0, end)), end: cursor + end + 1 };
      name += this.decodeAnsi(bytes);
    }
    throw new Error("CodeView ANSI name is not NUL-terminated.");
  }

  async utf8(offset: number): Promise<string> {
    return (await this.utf8Name(offset)).name;
  }

  // PDBMAP stores two Windows wchar_t stringZ paths, including record-local
  // terminators. Preserve literal BOMs, as for UTF-8 CodeView names.
  // https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L4565
  async utf16Name(offset: number): Promise<{ name: string; end: number }> {
    const decoder = new TextDecoder("utf-16le", { fatal: true, ignoreBOM: true });
    let value = "";
    for (let cursor = offset; cursor + 1 < this.size; cursor += 256) {
      const view = await this.view(cursor, Math.min(256, 2 * Math.floor((this.size - cursor) / 2)));
      const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
      let end = 0;
      while (end < view.byteLength && view.getUint16(end, true) !== 0) end += 2;
      if (end < view.byteLength) return {
        name: value + decoder.decode(bytes.subarray(0, end)), end: cursor + end + 2
      };
      value += decoder.decode(bytes, { stream: true });
    }
    throw new Error("CodeView UTF-16 path is not NUL-terminated.");
  }

  async utf8Name(offset: number): Promise<{ name: string; end: number }> {
    const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
    let value = "";
    for (let cursor = offset; cursor < this.size; cursor += 256) {
      const view = await this.view(cursor, Math.min(256, this.size - cursor));
      const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
      const end = bytes.indexOf(0);
      if (end >= 0) return { name: value + decoder.decode(bytes.subarray(0, end)), end: cursor + end + 1 };
      value += decoder.decode(bytes, { stream: true });
    }
    throw new Error("CodeView UTF-8 name is not NUL-terminated.");
  }
}
