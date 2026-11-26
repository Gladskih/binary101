import { deflateSync } from "node:zlib";

const pageObjects = [
  "<< /Type /Catalog /Pages 2 0 R >>",
  "<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
  "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << >> >>",
  "<< /Title (Proof of (nested) strings) >>"
];

const finish = (body: string, offset: number): File =>
  new File([Buffer.from(`${body}startxref\n${offset}\n%%EOF\n`, "latin1")], "modern.pdf");

const streamObject = (id: number, dictionary: string, data: Buffer, length = data.length): string =>
  `${id} 0 obj\n<< ${dictionary} /Length ${length} >>\nstream\n` +
  `${data.toString("latin1")}\nendstream\nendobj\n`;

export const createStreamPdf = (
  encoding: "plain" | "flate-png" | "unsupported" | "short" = "plain",
  infoIndex = 3,
  change: { xref?: string; objects?: string; length?: number; data?: Buffer } = {}
): File => {
  const pairs = pageObjects.map((_, index) =>
    `${index + 1} ${pageObjects.slice(0, index).join("").length}`
  ).join(" ") + "\n";
  const header = "%PDF-1.7\n";
  const objects = streamObject(5, change.objects ??
    `/Type /ObjStm /N 4 /First ${pairs.length} /Filter /FlateDecode`,
    deflateSync(pairs + pageObjects.join("")));
  const offset = header.length + objects.length;
  // ISO 32000-2, Table 18: free, compressed, and byte-offset entries with /W [1 2 2].
  const rows = [[0, 0, 0, 255, 255], ...[0, 1, 2, infoIndex].map(index => [2, 0, 5, 0, index]),
    [1, 0, header.length, 0, 0], [1, offset >> 8, offset & 255, 0, 0]];
  let fields = "/Type /XRef /Size 7 /W [1 2 2] /Root 1 0 R /Info 4 0 R";
  let data = Buffer.from(rows.flat());
  if (encoding === "flate-png") {
    // PNG Up filter encodes each byte as its difference from the previous row.
    data = deflateSync(Buffer.from(rows.flatMap((row, index) =>
      [2, ...row.map((byte, column) => byte - (rows[index - 1]?.[column] ?? 0))])));
    fields += " /Filter [/FlateDecode] /DecodeParms [<< /Predictor 12 /Columns 5 >>]";
  }
  if (encoding === "unsupported") fields += " /Filter /LZWDecode";
  if (encoding === "short") data = data.subarray(0, -1);
  return finish(header + objects +
    streamObject(6, change.xref ?? fields, change.data ?? data, change.length), offset);
};

const entry = (offset: number, generation: number, status: string): string =>
  `${String(offset).padStart(10, "0")} ${String(generation).padStart(5, "0")} ${status} \n`;

export const createHybridPdf = (deleted: boolean): File => {
  let body = "%PDF-1.7\n";
  const entries = pageObjects.slice(0, 3).map((dict, index) => {
    const offset = body.length;
    body += `${index + 1} 0 obj\n${dict}\nendobj\n`;
    return entry(offset, 0, "n");
  });
  const previous = body.length;
  body += "xref\n0 5\n" + entry(4, 65535, "f") + entries.join("") + entry(0, 0, "f") +
    `trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n${previous}\n%%EOF\n`;
  const objects = body.length;
  body += streamObject(5, "/Type /ObjStm /N 1 /First 4",
    Buffer.from("4 0 " + pageObjects[3], "ascii"));
  const supplement = body.length;
  body += streamObject(6, "/Type /XRef /Size 7 /Index [4 1] /W [1 1 0]", Buffer.from([2, 5]));
  const latest = body.length;
  body += "xref\n" + (deleted ? "4 1\n" + entry(0, 1, "f") : "") +
    "5 2\n" + entry(objects, 0, "n") + entry(supplement, 0, "n");
  return finish(body + `trailer\n<< /Size 7 /Root 1 0 R /Info 4 0 R /Prev ${previous} ` +
    `/XRefStm ${supplement} >>\n`, latest);
};

export const createRevisionPdf = (update: "live" | "free" | "generation" | "wrong-offset" |
  "header-generation" | "outside-file" | "cycle" | "encrypted"): File => {
  let body = "%PDF-1.7\n";
  const entries = pageObjects.map((dict, index) => {
    const offset = body.length;
    body += `${index + 1} 0 obj\n${dict}\nendobj\n`;
    return entry(offset, 0, "n");
  });
  const prior = body.length;
  body += "xref\n0 5\n" + entry(0, 65535, "f") + entries.join("") +
    `trailer\n<< /Size 5 /Root 1 0 R /Info 4 0 R >>\nstartxref\n${prior}\n%%EOF\n`;
  const offset = body.length;
  const generation = update === "generation" ? 1 : 0;
  body += `4 ${update === "header-generation" ? 1 : generation} obj\n` +
    "<< /Title (Latest revision) >>\nendobj\n";
  const latest = body.length;
  const infoOffset = update === "wrong-offset" ? "%PDF-1.7\n".length : offset;
  body += "xref\n4 1\n" + (update === "free" ? entry(0, 1, "f") :
    entry(update === "outside-file" ? 9999999999 : infoOffset, generation, "n"));
  const encrypt = update === "encrypted" ? " /Encrypt 7 0 R" : "";
  return finish(body + `trailer\n<< /Size 5 /Root 1 0 R /Info 4 0 R${encrypt} ` +
    `/Prev ${update === "cycle" ? latest : prior} >>\n`, latest);
};
