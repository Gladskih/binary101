
const encodingLabels = new Map<number, string>([
  // Windows code-page identifiers mapped to WHATWG TextDecoder labels.
  // https://learn.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
  // https://encoding.spec.whatwg.org/#names-and-labels
  [65001, "utf-8"], [1200, "utf-16le"], [1201, "utf-16be"], [20127, "ascii"],
  [874, "windows-874"], [932, "shift_jis"], [936, "gbk"], [949, "euc-kr"], [950, "big5"],
  [1250, "windows-1250"], [1251, "windows-1251"], [1252, "windows-1252"],
  [1253, "windows-1253"], [1254, "windows-1254"], [1255, "windows-1255"],
  [1256, "windows-1256"], [1257, "windows-1257"], [1258, "windows-1258"]
]);

const bomEncoding = (data: Uint8Array): string | null => {
  // Analyzer policy: prefer an explicit byte signature over potentially stale PE metadata.
  // U+FEFF signatures: FF FE (UTF-16LE), FE FF (UTF-16BE), EF BB BF (UTF-8).
  // https://www.unicode.org/faq/utf_bom.html#BOM
  if (data[0] === 0xff && data[1] === 0xfe) return "utf-16le";
  if (data[0] === 0xfe && data[1] === 0xff) return "utf-16be";
  if (data[0] === 0xef && data[1] === 0xbb && data[2] === 0xbf) return "utf-8";
  return null;
};

// Retain only a BOM prefix and decoded text; byte buffers belong to the range reader.
class RegistryTextDecoder {
  private prefix: number[] = [];
  private decoder: TextDecoder | null = null;
  private parts: string[] = [];
  private byteCount = 0;
  private nonAscii = false;
  // Analyzer fallback policy, not a PE/ATL default: preserve ASCII and expose legacy bytes
  // deterministically when the originating ACP is unknown. Non-ASCII always gets a warning.
  // Decoder definition: https://encoding.spec.whatwg.org/#single-byte-decoder
  private encoding = "windows-1252";
  constructor(private readonly codePage: number, private readonly issues: string[]) {}

  append(data: Uint8Array): void {
    this.byteCount += data.length;
    // US-ASCII has 7 bits: first excluded byte = 2^7 = 0x80 (RFC 20, section 2).
    // https://www.rfc-editor.org/rfc/rfc20.html#section-2
    this.nonAscii ||= data.some(byte => byte >= 0x80);
    let offset = 0;
    if (!this.decoder) {
      // Prefix length = max(UTF-8 BOM's 3 bytes, UTF-16 BOM's 2 bytes) = 3, across reads.
      // https://www.unicode.org/faq/utf_bom.html#BOM
      while (offset < data.length && this.prefix.length < 3) this.prefix.push(data[offset++]!);
      if (this.prefix.length < 3) return;
      this.start();
    }
    this.parts.push(this.decoder!.decode(data.subarray(offset), { stream: true }));
  }

  private start(): void {
    const prefix = new Uint8Array(this.prefix);
    this.encoding = bomEncoding(prefix) ?? encodingLabels.get(this.codePage) ?? "windows-1252";
    this.decoder = new TextDecoder(this.encoding);
    this.parts.push(this.decoder.decode(prefix, { stream: true }));
  }

  private encodingIssues(): void {
    if (this.nonAscii && !bomEncoding(new Uint8Array(this.prefix)) &&
        !encodingLabels.has(this.codePage)) {
      this.issues.push(this.codePage
        ? `ATL RGS: unsupported code page ${this.codePage}; Windows-1252 fallback is uncertain.`
        : "ATL RGS: ANSI code page is unspecified; Windows-1252 fallback is uncertain.");
    }
    if (this.encoding === "ascii" && this.nonAscii) {
      // WHATWG's ASCII label is Windows-1252; explicitly diagnose invalid US-ASCII.
      // https://encoding.spec.whatwg.org/#names-and-labels
      this.issues.push("ATL RGS: non-ASCII byte in a declared US-ASCII resource.");
    }
    // UTF-16 code unit = 16/8 = 2 octets; an odd byte count cannot contain whole units.
    // https://www.unicode.org/faq/utf_bom.html#utf16-1
    if (this.encoding.startsWith("utf-16") && this.byteCount % 2) {
      this.issues.push("ATL RGS: truncated UTF-16 code unit.");
    }
  }

  finish(): { text: string; encoding: string } {
    if (!this.decoder) this.start();
    this.parts.push(this.decoder!.decode());
    this.encodingIssues();
    const decoded = this.parts.join("");
    // TextDecoder's replacement mode emits U+FFFD on decoding errors.
    // https://encoding.spec.whatwg.org/#concept-encoding-process
    if (decoded.includes("\ufffd")) this.issues.push("ATL RGS: invalid encoded text.");
    const terminator = decoded.indexOf("\0");
    if (terminator >= 0 && /[^\0]/u.test(decoded.slice(terminator))) {
      this.issues.push("ATL RGS: non-padding data follows a NUL terminator; analysis stopped there.");
    }
    return { text: terminator < 0 ? decoded : decoded.slice(0, terminator), encoding: this.encoding };
  }
}

export const decodeRegistryText = (
  data: Uint8Array, codePage: number, issues: string[]
): { text: string; encoding: string } => {
  const decoder = new RegistryTextDecoder(codePage, issues);
  decoder.append(data);
  return decoder.finish();
};

export const decodeRegistryTextChunks = async (
  chunks: AsyncIterable<Uint8Array>, codePage: number, issues: string[]
): Promise<{ text: string; encoding: string }> => {
  const decoder = new RegistryTextDecoder(codePage, issues);
  for await (const chunk of chunks) decoder.append(chunk);
  return decoder.finish();
};
