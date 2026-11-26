export const createPdfObjects = (
  values: string[], trailer = "", name = "document-structure.pdf"
): File => {
  const free = "0000000000 65535 f \n";
  let body = "%PDF-1.7\n";
  const entries = values.map((value, index) => {
    const entry = String(body.length).padStart(10, "0") + " 00000 n \n";
    body += (index + 1) + " 0 obj\n" + value + "\nendobj\n";
    return entry;
  });
  const start = body.length;
  body += "xref\n0 " + (values.length + 1) + "\n" + free + entries.join("") +
    "trailer\n<< /Size " + (values.length + 1) + " /Root 1 0 R " + trailer +
    " >>\nstartxref\n" + start + "\n%%EOF\n";
  return new File([Buffer.from(body, "latin1")], name, { type: "application/pdf" });
};

export const createPdfWithEmbeddedFile = (): File => createPdfObjects([
  "<< /Type /Catalog /PageMode /UseNone /Pages 2 0 R /Names 7 0 R /AF [8 0 R 10 0 R] >>",
  "<< /Type /Pages /Count 2 /Kids [3 0 R 4 0 R] /MediaBox [0 0 612 792] /Rotate 90 >>",
  "<< /Type /Page /Parent 2 0 R /Resources << >> >>",
  "<< /Type /Pages /Parent 2 0 R /Kids [5 0 R] /Count 1 /CropBox [10 20 200 400] >>",
  "<< /Type /Page /Parent 4 0 R /MediaBox [321 456 -0.5 -2] /Rotate 0 /UserUnit 2 /Resources << >> >>",
  "<< /Kids [9 0 R] >>",
  "<< /EmbeddedFiles 6 0 R >>",
  "<< /Type /Filespec /F (fallback.txt) /UF (notes.txt) /Desc (Read &lt;notes&gt;) " +
    "/EF << /F 11 0 R /UF 11 0 R >> /AFRelationship /Data >>",
  "<< /Names [(index name) 8 0 R] >>",
  "<< /Type /Filespec /F (external.txt) /AFRelationship /Alternative >>",
  "<< /Type /EmbeddedFile /Length 4 /Subtype /text#2fplain /Params << /Size 4 >> >>\nstream\ntext\nendstream"
]);
