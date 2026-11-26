import assert from "node:assert/strict";
import { test } from "node:test";
import {
  decodePdfBytes, parseIndirectDictionary, readIndirectDictionary, readPdfText
} from "../../../../analyzers/pdf/object.js";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";

void test("PDF byte conversion preserves every 8-bit value across multiple chunks", () => {
  const bytes = Uint8Array.from({ length: 40_003 }, (_, index) => index % 256);
  const decoded = decodePdfBytes(bytes);
  assert.equal(decodePdfBytes(new Uint8Array()), "");
  assert.equal(decoded, Buffer.from(bytes).toString("latin1"));
});

void test("object dictionary preserves generation and position after comments", () => {
  const dictionary = "<< /Type /Pages >>";
  const text = "438 \t2 \r\n obj\n" + dictionary + "\n% endobj in a comment\r\nendobj\n";
  const object = parseIndirectDictionary(text, 100);
  assert.deepEqual(object?.ref, { objectNumber: 438, generation: 2 });
  assert.equal(object?.dictionary.raw, dictionary);
  assert.equal(object?.nextOffset, 100 + text.lastIndexOf("endobj"));
  assert.equal(object?.following, "endobj\n");
  assert.equal(parseIndirectDictionary("2 65535 obj << >>", 0)?.ref.generation, 65535);
});

for (const fragment of ["extra 1 0 obj << >>", "0 0 obj << >>", "9007199254740992 0 obj << >>",
  "1 9007199254740992 obj << >>", "1 65536 obj << >>", "1 0 object << >>", "1 0 obj <"]) {
  void test("rejects an unanchored or invalid indirect object " + fragment, () => {
    assert.equal(parseIndirectDictionary(fragment, 0), null);
  });
}

void test("object and PDF text readers use the requested file offset", async () => {
  const file = new File(["offset1 0 obj << >> endobj"], "reference.pdf");
  const reader = createFileRangeReader(file, 0, file.size);
  assert.equal(await readPdfText(reader, 6, 3), "1 0");
  assert.equal((await readIndirectDictionary(reader, 6))?.dictionary.raw, "<< >>");
  assert.equal(await readIndirectDictionary(reader, file.size), null);
});
