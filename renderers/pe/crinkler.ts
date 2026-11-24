import { hex, humanSize } from "../../binary-utils.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import type { PeCrinklerPackerFinding } from "../../analyzers/pe/packers/types.js";

const renderLayout = ({ layout }: PeCrinklerPackerFinding): string =>
  "<dl>" +
  renderDefinitionRow("Crinkler version marker", escapeHtml(layout.version),
    "Two digits written by Crinkler. Patch letters are not encoded here.") +
  renderDefinitionRow("Header profile", {
    compatibility: "Compatibility header", standard: "Standard header", tiny: "Tiny Header"
  }[layout.profile]) +
  renderDefinitionRow("Decompressor entry RVA", hex(layout.entryRva),
    "Entry RVA recorded at the PE32 field offset in this Crinkler header template.") +
  renderDefinitionRow("Decompressor file offset", hex(layout.entryOffset)) +
  renderDefinitionRow("Preferred image base", hex(layout.imageBase)) +
  renderDefinitionRow("SizeOfHeaders field", humanSize(layout.headerSize),
    "Value at the PE32 field offset. It does not measure the complete Crinkler stub.") +
  renderDefinitionRow("SizeOfImage field", humanSize(layout.imageSize),
    "Raw value at the PE32 field offset. Some bytes also serve as instructions.") +
  renderDefinitionRow("Unpacked data address", hex(layout.unpackedVa),
    "Destination address recorded in a decompressor instruction.") +
  renderDefinitionRow("Packed stream file offset", hex(layout.streamOffset),
    "Source address referenced by the decoder, relative to the preferred image base.") +
  "</dl>";

const renderParts = ({ parts }: PeCrinklerPackerFinding): string => {
  if (!parts?.length) return "";
  const rows = parts.map((part, index) =>
    `<tr><td class="peNumeric">${index + 1}</td>` +
    `<td class="peNumeric">${hex(part.offset)}</td>` +
    `<td class="peNumeric">${part.unpackedSize}</td>` +
    `<td class="peNumeric">${hex(part.encodedWeights, 8)}</td>` +
    `<td class="peNumeric">${part.models.length}</td><td>` +
    part.models.map(model =>
      `<code>${hex(model.contextMask, 2)}: ${model.weight}</code>`
    ).join(" ") + "</td></tr>"
  );
  return '<div class="tableWrap"><table class="table pePackerFinding__details">' +
    "<thead><tr><th>Part</th><th>File offset</th><th>Unpacked bytes</th>" +
    "<th>Weight mask</th><th>Models</th><th>Context mask and weight</th></tr></thead>" +
    `<tbody>${rows.join("")}</tbody></table></div>` +
    '<p class="smallNote">The part records describe unpacked sizes and models. ' +
    "The end of the compressed stream has not been verified.</p>";
};

const renderTiny = ({ tiny, decoded }: PeCrinklerPackerFinding): string => {
  if (!tiny) return "";
  return "<dl>" +
    renderDefinitionRow(decoded ? "Verified unpacked bytes" : "Declared unpacked bytes",
      String(tiny.size)) +
    renderDefinitionRow("Model mask", hex(tiny.model.mask, 8)) +
    renderDefinitionRow("Base weights", `${tiny.model.baseZero} / ${tiny.model.baseOne}`,
      "Base weight for zero / one.") +
    renderDefinitionRow("Boost factor", String(tiny.model.boost)) +
    (decoded ? renderDefinitionRow("Verified packed bytes", String(decoded.packedSize),
      "The decoded bytes reproduce this compressed span under canonical encoding.") : "") +
    "</dl>";
};

const renderTinyImports = ({ decoded }: PeCrinklerPackerFinding): string => {
  const imports = decoded?.imports;
  if (!imports) return "";
  return "<h4>Tiny Import resolver</h4><dl>" +
    renderDefinitionRow("DLL name list address", hex(imports.dllNamesVa)) +
    renderDefinitionRow("Import slot table address", hex(imports.tableVa)) +
    renderDefinitionRow("Export name hash multiplier", hex(imports.hashMultiplier)) +
    renderDefinitionRow("Export name hash shift", String(imports.hashShift)) +
    '</dl><p class="smallNote">The resolver fills slots from exports on the target Windows ' +
    "system. The slot addresses alone do not identify imported functions.</p>";
};

export const renderCrinklerFindingDetails = (finding: PeCrinklerPackerFinding): string =>
  renderLayout(finding) + renderParts(finding) + renderTiny(finding) +
  renderTinyImports(finding);
