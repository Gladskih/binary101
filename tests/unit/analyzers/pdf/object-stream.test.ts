import assert from "node:assert/strict";
import { test } from "node:test";
import { deflateSync } from "node:zlib";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { parseIndirectDictionary } from "../../../../analyzers/pdf/object.js";
import { readObjectStream } from "../../../../analyzers/pdf/object-stream.js";
import { expectDefined } from "../../../helpers/expect-defined.js";

const read = (index: string, body: string, count: number, params = "null") => {
  const encoded = deflateSync(index + body);
  const header = "17 0 obj\n<< /Type /ObjStm /N " + count + " /First " + index.length +
    " /Length " + encoded.length + " /Filter /FlateDecode /DecodeParms " + params + " >>\nstream\n";
  const file = new File([header, encoded, "\nendstream\nendobj"], "object-stream.pdf");
  return readObjectStream(createFileRangeReader(file, 0, file.size),
    expectDefined(parseIndirectDictionary(header, 0)));
};

void test("object streams use header order and allow non-sequential object numbers", async () => {
  const index = " \t17 0 % comment\r\n8 5\n";
  const stream = await read(index, "<< >><< /Length 0 >>", 2, "<< /Predictor 1 >>");
  assert.deepEqual(stream.entries, [{ objectNumber: 17, offset: 0 }, { objectNumber: 8, offset: 5 }]);
  assert.equal(Buffer.from(stream.body).toString("latin1"), "<< >><< /Length 0 >>");
});

for (const [index, reason] of [
  ["0 0 2 5\n", "invalid object stream number"],
  ["1 0 1 5\n", "invalid object stream number"],
  ["1 0 /N 5\n", "invalid object stream number"],
  ["1 1 2 5\n", "invalid object stream offset"],
  ["1 0 2 0\n", "invalid object stream offset"],
  ["1 0 2 10\n", "invalid object stream offset"]
] as const) {
  void test("rejects a malformed object-stream index " + JSON.stringify(index), async () => {
    await assert.rejects(read(index, "<< >><< >>", 2), { message: reason });
  });
}

void test("object streams reject a header that leaves no object bytes", async () => {
  await assert.rejects(read("1 0\n", "", 1), { message: "/First lies outside the decoded object stream" });
});

void test("object streams warn for unsupported indirect decode parameters", async () => {
  await assert.rejects(read("1 0\n", "<< >>", 1, "9 0 R"),
    { message: "unsupported object stream /DecodeParms" });
});
