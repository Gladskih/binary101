"use strict";

import { MockFile } from "../helpers/mock-file.mjs";

const encoder = new TextEncoder();

export const createPdfWithXrefStream = () => {
  const content = [
    "%PDF-1.5",
    "1 0 obj",
    "<</Type /XRef /Size 1>>",
    "stream",
    "0000", // bogus stream
    "endstream",
    "endobj",
    "startxref",
    "9",
    "%%EOF"
  ].join("\n");
  return new MockFile(encoder.encode(content), "xref-stream.pdf", "application/pdf");
};
