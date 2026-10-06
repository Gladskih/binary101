import { escapeHtml } from "../../html-utils.js";
import { DWARF_ATTRIBUTE, DWARF_TAG } from "../../analyzers/dwarf/constants.js";
import { dwarfNumericValue, dwarfStringValue, dwarfUnitRoot } from "../../analyzers/dwarf/attribute-values.js";
import { dwarfTagLabel } from "../../analyzers/dwarf/tag-names.js";
import { dwarfAttributeName } from "../../analyzers/dwarf/attribute-names.js";
import {
  createDwarfDieIndex, inheritedDwarfAttribute, resolveDwarfReference, isDwarfDieReference,
  type DwarfDieIndex, type DwarfDieRecord
} from "../../analyzers/dwarf/references.js";
import type { DwarfAnalysis, DwarfAttribute } from "../../analyzers/dwarf/types.js";
import { dwarfTypeName } from "./type-names.js";
import { dwarfLineFile, dwarfSourcePath } from "./source-paths.js";
import { dwarfExpressionText } from "./expressions.js";
import { dwarfCodeSize } from "../../analyzers/dwarf/code-ranges.js";
import { dwarfAttributeMeaning } from "./attribute-meanings.js";

const nameOf = (index: DwarfDieIndex, record: DwarfDieRecord): string | null =>
  dwarfStringValue(inheritedDwarfAttribute(index, record, DWARF_ATTRIBUTE.name)?.attribute.value);

const qualifiedName = (index: DwarfDieIndex, record: DwarfDieRecord): string => {
  const names = [nameOf(index, record) ?? "(unnamed)"];
  let parent = record.die.parentOffset == null ? undefined
    : index.byOffset.get(`${record.unit.sectionName}:${record.die.parentOffset}`);
  const visited = new Set([record]);
  while (parent && !visited.has(parent)) {
    visited.add(parent);
    if (parent.die.parentOffset == null) break;
    const name = nameOf(index, parent);
    if (name) names.unshift(name);
    parent = parent.die.parentOffset == null ? undefined
      : index.byOffset.get(`${record.unit.sectionName}:${parent.die.parentOffset}`);
  }
  return names.join("::");
};

const attributeText = (
  index: DwarfDieIndex, record: DwarfDieRecord, attribute: DwarfAttribute
): string | null => {
  const reference = resolveDwarfReference(index, record, attribute);
  if (reference) return nameOf(index, reference) ?? dwarfTypeName(index, reference);
  if (isDwarfDieReference(attribute.form)) return "unresolved DIE reference";
  if (attribute.value.kind === "string") return attribute.value.value;
  if (attribute.value.kind === "flag") return attribute.value.value ? "yes" : "no";
  if (attribute.value.kind === "block") return `${attribute.value.value.length} bytes`;
  if (attribute.value.kind === "expression") return dwarfExpressionText(attribute.value.operations);
  return listAttributeText(attribute);
};

const listAttributeText = (attribute: DwarfAttribute): string | null => {
  if (attribute.value.kind === "ranges") {
    return `${attribute.value.entries.length} code ranges`;
  }
  if (attribute.value.kind === "locations") {
    return attribute.value.entries.map(entry =>
      `${entry.range == null ? "default location" : `${entry.range.end - entry.range.start} code bytes`}: ` +
      dwarfExpressionText(entry.operations)
    ).join("; ");
  }
  const numeric = dwarfNumericValue(attribute.value);
  return numeric == null ? null : dwarfAttributeMeaning(attribute.name, numeric);
};

// Infrastructure offsets and raw machine addresses are retained by the analyzer.
// The entity table focuses on source-level facts instead of requiring address arithmetic.
const infrastructureAttributes = new Set<number>([
  DWARF_ATTRIBUTE.lowPc, DWARF_ATTRIBUTE.highPc, DWARF_ATTRIBUTE.ranges,
  DWARF_ATTRIBUTE.statementList, DWARF_ATTRIBUTE.stringOffsetsBase,
  DWARF_ATTRIBUTE.addressBase, DWARF_ATTRIBUTE.rangeListsBase, DWARF_ATTRIBUTE.locationListsBase,
  DWARF_ATTRIBUTE.declarationFile, DWARF_ATTRIBUTE.declarationLine, DWARF_ATTRIBUTE.declarationColumn,
  DWARF_ATTRIBUTE.name, DWARF_ATTRIBUTE.type, DWARF_ATTRIBUTE.abstractOrigin,
  DWARF_ATTRIBUTE.specification
]);

const renderAttributes = (index: DwarfDieIndex, record: DwarfDieRecord): string => {
  const rows = record.die.attributes.filter(attribute =>
    !infrastructureAttributes.has(attribute.name)
  ).map(attribute => {
    const text = attributeText(index, record, attribute);
    return text == null ? "" : `<tr><td>${escapeHtml(
      dwarfAttributeName(attribute.name).replace("DW_AT_", "").replaceAll("_", " ")
    )}</td>` +
      `<td>${escapeHtml(text)}</td></tr>`;
  }).join("");
  if (!rows) return "";
  return `<details><summary>Attributes</summary><div class="tableWrap"><table class="table">` +
    `<thead><tr><th>Attribute</th><th>Value</th></tr></thead><tbody>${rows}</tbody></table></div></details>`;
};

const declarationFilePath = (dwarf: DwarfAnalysis, owner: DwarfDieRecord,
  fileIndex: bigint | null, statementListOffset: bigint | undefined): string => {
  if (fileIndex == null) return "file not recorded";
  const program = dwarf.linePrograms.find(item => BigInt(item.offset) === statementListOffset);
  if (!program) return `unresolved file ${fileIndex}`;
  const file = dwarfLineFile(program, fileIndex);
  return file ? dwarfSourcePath(program, file, owner.unit) : `unresolved file ${fileIndex}`;
};

const declarationSource = (
  dwarf: DwarfAnalysis, index: DwarfDieIndex, record: DwarfDieRecord
): string => {
  const source = inheritedDwarfAttribute(index, record, DWARF_ATTRIBUTE.declarationFile);
  const owner = source?.record ?? record;
  const fileIndex = dwarfNumericValue(source?.attribute.value);
  const root = dwarfUnitRoot(owner.unit);
  const line = dwarfNumericValue(
    inheritedDwarfAttribute(index, record, DWARF_ATTRIBUTE.declarationLine)?.attribute.value
  );
  const column = dwarfNumericValue(
    inheritedDwarfAttribute(index, record, DWARF_ATTRIBUTE.declarationColumn)?.attribute.value
  );
  const path = declarationFilePath(dwarf, owner, fileIndex, root?.statementListOffset);
  return path + (line == null ? "" : `:${line}`) + (column == null ? "" : `:${column}`);
};

const renderEntity = (dwarf: DwarfAnalysis, index: DwarfDieIndex, record: DwarfDieRecord): string => {
  const type = inheritedDwarfAttribute(index, record, DWARF_ATTRIBUTE.type);
  const referenced = type ? resolveDwarfReference(index, type.record, type.attribute) : null;
  const typeName = referenced ? dwarfTypeName(index, referenced) : type ? "unresolved type" : "-";
  return `<tr><td>${escapeHtml(dwarfTagLabel(record.die.tag).replaceAll("_", " "))}</td>` +
    `<td class="mono">${escapeHtml(qualifiedName(index, record))}</td>` +
    `<td>${escapeHtml(typeName)}</td>` +
    `<td class="mono">${escapeHtml(declarationSource(dwarf, index, record))}</td>` +
    `<td class="dwarfTable__numeric">${dwarfCodeSize(record.die) ?? "-"}</td>` +
    `<td>${renderAttributes(index, record)}</td></tr>`;
};

export const renderDwarfEntities = (dwarf: DwarfAnalysis): string => {
  const index = createDwarfDieIndex(dwarf.units);
  const entities = index.records.filter(record => record.die.parentOffset != null &&
    (nameOf(index, record) || record.die.tag === DWARF_TAG.inlinedSubroutine));
  if (!entities.length) return "";
  return `<h5>Program entities</h5><div class="tableWrap"><table class="table"><thead><tr>` +
    `<th>Kind</th><th>Name / scope</th><th>Type</th><th>Declaration</th>` +
    `<th>Code bytes</th><th>Details</th>` +
    `</tr></thead><tbody>${entities.map(record => renderEntity(dwarf, index, record)).join("")}` +
    `</tbody></table></div>`;
};
