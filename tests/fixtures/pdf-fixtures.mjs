"use strict";

import { MockFile } from "../helpers/mock-file.mjs";

const encoder = new TextEncoder();

export const createPdfMissingStartxref = () => {
  const content = "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n";
  return new MockFile(encoder.encode(content), "missing-startxref.pdf", "application/pdf");
};

export const createPdfWithBadXref = () => {
  const content = [
    "%PDF-1.4",
    "xref",
    "0 1",
    "0000000000 65535 f ",
    "trailer",
    "<< /Size 1 >>",
    "startxref",
    "999999",
    "%%EOF"
  ].join("\n");
  return new MockFile(encoder.encode(content), "bad-xref.pdf", "application/pdf");
};
