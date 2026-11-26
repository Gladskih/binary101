import assert from "node:assert/strict";
import { test } from "node:test";
import { deflateSync } from "node:zlib";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { parseIndirectDictionary } from "../../../../analyzers/pdf/object.js";
import { decodeStructureStream } from "../../../../analyzers/pdf/structure-stream.js";
import { expectDefined } from "../../../helpers/expect-defined.js";

const decode = (fields: string, data: Buffer, suffix: string, limit: number, marker = "stream\n") => {
  const header = "20 0 obj\n<< " + fields + " >>\n" + marker;
  const bytes = Buffer.from(header + data.toString("latin1") + suffix, "latin1");
  const file = new File([bytes], "stream.pdf");
  const reader = createFileRangeReader(file, 0, file.size);
  const object = expectDefined(parseIndirectDictionary(header, 0));
  return decodeStructureStream(reader, object, limit);
};

void test("honors direct Length, CRLF markers and a byte limit equal to the stored size", async () => {
  const data = Buffer.from([0, 255, 248]);
  const result = await decode("/Length 3", data, "\r\nendstream\r\n% comment\r\nendobj", 3, "stream\r\n");
  assert.deepEqual([...result.bytes], [0, 255, 248]);
  assert.equal(result.parameters, undefined);
  await assert.rejects(decode("/Length 3", data, "\nendstream\nendobj", 2),
    { message: "stream exceeds the decoded byte limit" });
});

void test("combines multiple Flate output chunks and retains the selected DecodeParms", async () => {
  const expected = Buffer.alloc(128 * 1024).map((_, index) => index % 239);
  const data = deflateSync(expected);
  const fields = "/Length " + data.length + " /Filter [/FlateDecode] /DecodeParms [<< /Predictor 1 >>]";
  const result = await decode(fields, data, "\nendstream\nendobj", expected.length);
  assert.deepEqual(Buffer.from(result.bytes), expected);
  assert.equal(result.parameters, "<< /Predictor 1 >>");
});

for (const [fields, suffix, marker, error] of [
  ["", "\nendstream\nendobj", "stream\n", "missing stream marker or direct /Length"],
  ["/Length 7 0 R", "\nendstream\nendobj", "stream\n", "missing stream marker or direct /Length"],
  ["/Length 0", "\nendstream\nendobj", "stream\r", "missing stream marker or direct /Length"],
  ["/Length 0", "\nendstream\nnoise endobj", "stream\n", "stream /Length does not lead to endstream and endobj"],
  ["/Length 0", "\nendstreaming\nendobj", "stream\n", "stream /Length does not lead to endstream and endobj"],
  ["/Length 0", "x\nendstream\nendobj", "stream\n", "stream /Length does not lead to endstream and endobj"],
  ["/Length 0", "\nendstream\nendobject", "stream\n", "stream /Length does not lead to endstream and endobj"]
] as const) {
  void test("bounds the stream using its syntax and length", async () => {
    await assert.rejects(decode(fields, Buffer.alloc(0), suffix, 0, marker), { message: error });
  });
}

for (const suffix of ["endstream\nendobj", "\rendstream\nendobj", "\nendstream\nendobj% note"]) {
  void test("accepts endstream framing supported by the declared byte length", async () => {
    const result = await decode("/Length 1", Buffer.from("x"), suffix, 1);
    assert.deepEqual([...result.bytes], [120]);
  });
}
