import type { LegacyCodeViewReader } from "./legacy-codeview-reader.js";

const decodeChunk = (decoder: TextDecoder, value: string | null, bytes: Uint8Array): string | null => {
  if (value === null) return null;
  try { return value + decoder.decode(bytes, { stream: true }); }
  catch { return null; }
};
const finishUtf8 = (decoder: TextDecoder, value: string | null): string | null => {
  if (value === null) return null;
  try { return value + decoder.decode(); }
  catch { return null; }
};

// Modern Delphi emits UTF-8. Old ANSI payloads have no recorded code page.
// Decode both in one bounded pass so invalid UTF-8 can retain all original text
// through an explicitly warned Windows-1252 fallback, without rereading names.
// https://github.com/csm101/delphi-visual-studio-code-debugger/blob/580b258063a37e6e6bd93a9a7593e0b8cc8a9d06/docs/TD32_FORMAT_NOTES.md#names-section-sst_names
export const readTd32Text = async (reader: LegacyCodeViewReader, offset: number) => {
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  const ansiDecoder = new TextDecoder("windows-1252", { ignoreBOM: true });
  let utf8: string | null = "";
  let ansi = "";
  for (let cursor = offset; cursor < reader.size; cursor += 256) {
    const view = await reader.view(cursor, Math.min(256, reader.size - cursor));
    const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    const end = bytes.indexOf(0);
    const text = end < 0 ? bytes : bytes.subarray(0, end);
    utf8 = decodeChunk(decoder, utf8, text);
    ansi += ansiDecoder.decode(text, { stream: true });
    if (end >= 0) {
      utf8 = finishUtf8(decoder, utf8);
      return { name: utf8 ?? ansi, end: cursor + end + 1, encoding: utf8 === null ? "Windows-1252" : "UTF-8" };
    }
  }
  throw new Error("TD32 name is not NUL-terminated.");
};
