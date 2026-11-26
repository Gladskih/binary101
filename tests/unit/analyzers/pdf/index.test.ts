"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { deflateSync } from "node:zlib";
import { parsePdf } from "../../../../analyzers/pdf/index.js";
import { createPdfFile } from "../../../fixtures/document-sample-files.js";
import { createPdfMissingStartxref, createPdfWithBadXref } from "../../../fixtures/pdf-fixtures.js";
import { createPdfWithXrefStream } from "../../../fixtures/pdf-corrupt-stream.js";
import { createHybridPdf, createRevisionPdf, createStreamPdf } from "../../../fixtures/pdf-modern.js";
import { expectDefined } from "../../../helpers/expect-defined.js";

void test("parsePdf warns when startxref is missing", async () => {
  const pdf = expectDefined(await parsePdf(createPdfMissingStartxref()));
  assert.ok(pdf.issues.some(issue => issue.toLowerCase().includes("startxref")));
});

void test("parsePdf warns when startxref points outside file", async () => {
  const pdf = expectDefined(await parsePdf(createPdfWithBadXref()));
  assert.ok(pdf.issues.some(issue => issue.toLowerCase().includes("offset")));
});

void test("parsePdf parses minimal valid PDF", async () => {
  const pdf = expectDefined(await parsePdf(createPdfFile()));
  assert.ok(pdf.header);
  assert.equal(pdf.revisions[0]?.primary.kind, "table");
});

void test("parsePdf notes xref stream detection", async () => {
  const pdf = expectDefined(await parsePdf(createPdfWithXrefStream()));
  assert.ok(pdf.issues.some(issue => issue.toLowerCase().includes("cross-reference stream")));
});

for (const encoding of ["plain", "flate-png"] as const) {
  void test(`parsePdf resolves compressed dictionaries from a ${encoding} xref stream`, async () => {
    const pdf = expectDefined(await parsePdf(createStreamPdf(encoding)));
    assert.equal(pdf.pages?.count, 1);
    assert.equal(pdf.info?.title, "Proof of (nested) strings");
    assert.deepEqual(pdf.issues, []);
  });
}

for (const [encoding, warning] of [["unsupported", "filter"], ["short", "row"]] as const) {
  void test(`parsePdf reports an unreadable ${encoding} xref stream`, async () => {
    const pdf = expectDefined(await parsePdf(createStreamPdf(encoding)));
    assert.equal(pdf.catalog, null);
    assert.ok(pdf.issues.some(issue => issue.includes(warning)));
  });
}

void test("parsePdf rejects an xref index pointing to a different compressed object", async () => {
  const pdf = expectDefined(await parsePdf(createStreamPdf("plain", 2)));
  assert.equal(pdf.pages?.count, 1);
  assert.equal(pdf.info, null);
  assert.match(pdf.issues.join("\n"), /object stream index/);
});

void test("parsePdf resolves unchanged objects across revisions and prefers the newest object", async () => {
  const pdf = expectDefined(await parsePdf(createRevisionPdf("live")));
  assert.equal(pdf.pages?.count, 1);
  assert.equal(pdf.info?.title, "Latest revision");
  assert.deepEqual(pdf.issues, []);
});

for (const [update, warning] of [
  ["free", "free"], ["generation", "generation"], ["wrong-offset", "header"],
  ["header-generation", "header"], ["outside-file", "outside the file"], ["encrypted", "/Encrypt"]
] as const) {
  void test(`parsePdf leaves Info unresolved after update: ${update}`, async () => {
    const pdf = expectDefined(await parsePdf(createRevisionPdf(update)));
    assert.equal(pdf.pages?.count, 1);
    assert.equal(pdf.info, null);
    assert.ok(pdf.issues.some(issue => issue.includes(warning)));
  });
}

void test("parsePdf terminates a cyclic /Prev chain", async () => {
  const pdf = expectDefined(await parsePdf(createRevisionPdf("cycle")));
  assert.match(pdf.issues.join("\n"), /cycle/);
});

void test("parsePdf resolves a supplement before the preceding xref table", async () => {
  const pdf = await parsePdf(createHybridPdf(false));
  assert.equal(pdf.revisions[0]?.supplement?.kind, "stream");
  assert.equal(pdf.revisions[1]?.primary.kind, "table");
  assert.equal(pdf.pages?.count, 1);
  assert.equal(pdf.info?.title, "Proof of (nested) strings");
  assert.deepEqual(pdf.issues, []);
});

void test("parsePdf honors an explicit free entry in the table of a hybrid revision", async () => {
  const pdf = await parsePdf(createHybridPdf(true));
  assert.equal(pdf.pages?.count, 1);
  assert.equal(pdf.info, null);
  assert.match(pdf.issues.join("\n"), /entry is free/);
});

const xrefFields = "/Type /XRef /Size 7 /W [1 2 2] /Root 1 0 R /Info 4 0 R";

for (const [change, warning] of [
  [{ xref: xrefFields.replace("/Size 7", "/Size 0") }, /invalid \/Size/],
  [{ xref: xrefFields.replace("/Size 7", "/Size 100001") }, /xref entry limit/],
  [{ xref: xrefFields.replace("[1 2 2]", "[1 2]") }, /\/W field widths/],
  [{ xref: xrefFields.replace("[1 2 2]", "[1 2000000 2]") }, /declared row layout exceeds/],
  [{ xref: xrefFields.replace("[1 2 2]", "[0 0 0]") }, /zero-width row layout/],
  [{ xref: xrefFields + " /Index [0 4 3 3]" }, /overlapping/],
  [{ xref: xrefFields + " /Index [4 4]" }, /out-of-range/],
  [{ xref: xrefFields + " /Index []" }, /invalid \/Index/],
  [{ xref: xrefFields + " /Index [0 3 7]" }, /invalid \/Index/],
  [{ xref: xrefFields + " /Filter /FlateDecode" }, /Cross-reference stream/],
  [{ xref: xrefFields + " /Filter [/FlateDecode /ASCII85Decode]" }, /filter chain/],
  [{ xref: xrefFields + " /DecodeParms [null null]" }, /\/DecodeParms array/],
  [{ xref: xrefFields + " /F (elsewhere)" }, /external stream/],
  [{ length: 1 }, /endstream and endobj/],
  [{ length: 4096 }, /extends beyond the file/],
  [{ length: 8388609 }, /stored stream exceeds/],
  [{ objects: "/Type /ObjStm /N -2 /First 16 /Filter /FlateDecode" }, /invalid or oversized/],
  [{ objects: "/Type /ObjStm /N 4 /First 1024 /Filter /FlateDecode" }, /\/First lies outside/],
  [{ objects: "/Type /ObjStm /N 2 /First 6 /Filter /FlateDecode" }, /invalid object stream offset/],
  [{ objects: "/Type /ObjStm /N 1 /First 16 /Filter /FlateDecode /DecodeParms << /Predictor 2 >>" },
    /unsupported object stream \/DecodeParms/],
  [{ objects: "/Type /Wrong /N 4 /First 16 /Filter /FlateDecode" }, /expected \/Type \/ObjStm/]
] as const) {
  void test("parsePdf reports " + warning, async () => {
    const pdf = await parsePdf(createStreamPdf("plain", 3, change));
    assert.equal(pdf.catalog, null);
    assert.match(pdf.issues.join("\n"), warning);
  });
}

void test("parsePdf does not call arrayBuffer on the whole file", async () => {
  const modern = createStreamPdf("flate-png");
  class RangeOnlyFile extends File {
    override arrayBuffer(): Promise<ArrayBuffer> {
      throw new Error("whole-file read");
    }
  }
  const pdf = await parsePdf(new RangeOnlyFile([modern], modern.name));
  assert.equal(pdf.pages?.count, 1);
});

void test("parsePdf treats null optional filter and file specifications as absent", async () => {
  const pdf = await parsePdf(createStreamPdf("plain", 3, {
    xref: xrefFields + " /Filter null /F null /DecodeParms << /Predictor 12 /Columns 5 >>"
  }));
  assert.equal(pdf.pages?.count, 1);
  assert.deepEqual(pdf.issues, []);
});

void test("parsePdf rejects xref fields beyond numerical precision", async () => {
  const pdf = await parsePdf(createStreamPdf("plain", 3, {
    xref: "/Type /XRef /Size 2 /Index [1 1] /W [0 8 0] /Root 1 0 R",
    data: Buffer.from("0020000000000000", "hex")
  }));
  assert.equal(pdf.revisions[0]?.primary.entries, null);
  assert.match(pdf.issues.join("\n"), /safe integer range/);
});

void test("parsePdf bounds inflated xref bytes even when the stored stream is small", async () => {
  const pdf = await parsePdf(createStreamPdf("plain", 3, {
    xref: xrefFields + " /Filter /FlateDecode", data: deflateSync(Buffer.alloc(9 * 1024 * 1024))
  }));
  assert.match(pdf.issues.join("\n"), /decoded stream exceeds the byte limit/);
});

void test("parsePdf retains unknown xref entry types without resolving them as objects", async () => {
  // Table 18 uses the first byte as the type and interprets unrecognised types as null objects.
  const pdf = await parsePdf(createStreamPdf("plain", 3, {
    xref: "/Type /XRef /Size 2 /Index [1 1] /W [1 1 1] /Root 1 0 R", data: Buffer.of(3, 12, 34)
  }));
  assert.deepEqual(pdf.revisions[0]?.primary.entries, [
    { objectNumber: 1, kind: "unknown", type: 3, second: 12, third: 34 }
  ]);
  assert.equal(pdf.catalog, null);
  assert.match(pdf.issues.join("\n"), /unknown cross-reference entry type/);
});

for (const [from, to, message] of [
  ["/Root 1 0 R", "/Lost 1 0 R", /Trailer lacks a valid \/Root/],
  ["/Type /Catalog", "/Type /Unknown", /missing \/Type \/Catalog/],
  ["/Pages 2 0 R", "/Other 2 0 R", /Catalog lacks a valid \/Pages/],
  ["/Type /Pages", "/Type /Other", /missing \/Type \/Pages/],
  ["/Count 1", "/Count /", /root lacks a valid \/Count/],
  ["endobj", "endxxx", /does not terminate with endobj/]
] as const) {
  void test("parsePdf reports " + message, async () => {
    // Replace equal-length strings so the xref offsets still target the same objects.
    const text = Buffer.from(createPdfFile().data).toString("latin1").replace(from, to);
    const pdf = await parsePdf(new File([Buffer.from(text, "latin1")], "broken.pdf"));
    assert.equal(pdf.pages?.count ?? null, null);
    assert.match(pdf.issues.join("\n"), message);
  });
}
