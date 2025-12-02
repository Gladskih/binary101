"use strict";

import { MockFile } from "../helpers/mock-file.js";

const encoder = new TextEncoder();

export const createFb2File = () => {
  const xml = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    "<FictionBook>",
    "<description><title-info><book-title>Example</book-title></title-info></description>",
    "<body><section><p>Hello world</p></section></body>",
    "</FictionBook>"
  ].join("\n");
  return new MockFile(encoder.encode(xml), "sample.fb2", "text/xml");
};

export const createPdfFile = () => {
  const header = "%PDF-1.4\n";
  const obj1 = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";
  const obj2 = "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n";
  const obj3 =
    "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>\nendobj\n";
  const obj4 = "4 0 obj\n<< /Length 11 >>\nstream\nHello World\nendstream\nendobj\n";

  const offsets: number[] = [];
  let cursor = 0;
  const add = (segment: string): string => {
    offsets.push(cursor);
    cursor += Buffer.byteLength(segment, "latin1");
    return segment;
  };

  const body = [add(header), add(obj1), add(obj2), add(obj3), add(obj4)].join("");
  const [, obj1Offset, obj2Offset, obj3Offset, obj4Offset] = offsets as [
    number,
    number,
    number,
    number,
    number
  ];
  const xrefOffset = cursor;
  const pad = (value: number): string => value.toString().padStart(10, "0");
  const xref =
    "xref\n0 5\n" +
    `${pad(0)} 65535 f \n` +
    `${pad(obj1Offset)} 00000 n \n` +
    `${pad(obj2Offset)} 00000 n \n` +
    `${pad(obj3Offset)} 00000 n \n` +
    `${pad(obj4Offset)} 00000 n \n`;
  const trailer = `trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
  const pdfText = body + xref + trailer;
  return new MockFile(encoder.encode(pdfText), "sample.pdf", "application/pdf");
};
