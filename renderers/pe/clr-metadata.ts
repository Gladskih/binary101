"use strict";

import { hex } from "../../binary-utils.js";
import { renderDefinitionRow, renderFlagChips, escapeHtml } from "../../html-utils.js";
import type {
  PeClrCustomAttributeInfo,
  PeClrMetadataIndex,
  PeClrMetadataTables,
  PeClrMethodSignature,
  PeClrTypeDefinitionInfo
} from "../../analyzers/pe/clr/types.js";

const MAX_RENDERED_ROWS = 80;

// ECMA-335 II.24.2.6 defines the low three HeapSizes bits. CoreCLR's
// CMiniMdSchemaBase adds the remaining named schema flags in m_heaps:
// https://github.com/dotnet/runtime/blob/main/src/coreclr/md/inc/metamodel.h
const METADATA_HEAP_FLAGS: Array<[number, string, string?]> = [
  [0x01, "STRING_4", "Indexes into #Strings are 4 bytes."],
  [0x02, "GUID_4", "Indexes into #GUID are 4 bytes."],
  [0x04, "BLOB_4", "Indexes into #Blob are 4 bytes."],
  [0x08, "PADDING", "CoreCLR schema padding bit."],
  [0x20, "DELTA_ONLY", "Only edit-and-continue deltas were persisted."],
  [0x40, "EXTRA_DATA", "An extra 4-byte schema value follows the row-count array."],
  [0x80, "HAS_DELETE", "Metadata can contain _Delete tokens."]
];

const dash = (value: string | number | boolean | null | undefined): string =>
  value == null || value === "" ? "-" : escapeHtml(value);

const indexText = (index: PeClrMetadataIndex): string =>
  index.row === 0 ? "-" : `${index.table} #${index.row}${index.valid ? "" : " (invalid)"}`;

const signatureText = (signature: PeClrMethodSignature | undefined): string => {
  if (!signature) return "-";
  const args = signature.parameterTypes.map(type => type || "?").join(", ");
  return `${signature.returnType || "?"} (${args})`;
};

const fullMethodName = (ownerType: string | null, methodName: string | null): string =>
  ownerType ? `${ownerType}::${methodName || "?"}` : methodName || "?";

const methodCount = (typeDef: PeClrTypeDefinitionInfo): string => {
  if (!typeDef.methodStart || typeDef.methodEnd == null) return "0";
  return String(typeDef.methodEnd - typeDef.methodStart + 1);
};

const limitNote = (total: number): string =>
  total > MAX_RENDERED_ROWS
    ? `<div class="smallNote">Showing first ${MAX_RENDERED_ROWS} of ${total} row(s).</div>`
    : "";

const renderSimpleTable = (
  title: string,
  headers: string[],
  rows: string[][]
): string => {
  if (!rows.length) return "";
  const body = rows.slice(0, MAX_RENDERED_ROWS)
    .map(row => `<tr>${row.map(cell => `<td>${cell}</td>`).join("")}</tr>`)
    .join("");
  return `<details style="margin-top:.35rem"><summary>${escapeHtml(title)} (${rows.length})</summary>` +
    limitNote(rows.length) +
    `<table class="table" style="margin-top:.35rem"><thead><tr>` +
    headers.map(header => `<th>${escapeHtml(header)}</th>`).join("") +
    `</tr></thead><tbody>${body}</tbody></table></details>`;
};

const targetFrameworkAttribute = (
  metadata: PeClrMetadataTables
): PeClrCustomAttributeInfo | null =>
  metadata.customAttributes.find(attr =>
    attr.parent.table === "Assembly" &&
    attr.attributeType?.endsWith("TargetFrameworkAttribute")
  ) || null;

const renderTargetFramework = (metadata: PeClrMetadataTables): string => {
  const attr = targetFrameworkAttribute(metadata);
  if (!attr) return "";
  const frameworkName = attr.fixedArguments[0]?.value;
  const displayName = attr.namedArguments.find(arg => arg.name === "FrameworkDisplayName")?.value;
  return `<details style="margin-top:.35rem" open><summary>Target framework</summary><dl>` +
    renderDefinitionRow("FrameworkName", dash(frameworkName), "TargetFrameworkAttribute constructor argument.") +
    renderDefinitionRow("FrameworkDisplayName", dash(displayName), "TargetFrameworkAttribute FrameworkDisplayName named property.") +
    `</dl></details>`;
};

const renderAssembly = (metadata: PeClrMetadataTables): string => {
  if (!metadata.assembly) return "";
  return `<details style="margin-top:.35rem" open><summary>Assembly identity</summary><dl>` +
    renderDefinitionRow("Name", dash(metadata.assembly.name), "Assembly table Name column.") +
    renderDefinitionRow("Version", escapeHtml(metadata.assembly.version), "Assembly table version columns.") +
    renderDefinitionRow("Culture", dash(metadata.assembly.culture), "Assembly culture string.") +
    renderDefinitionRow("Flags", hex(metadata.assembly.flags, 8), "AssemblyFlags bitmask.") +
    renderDefinitionRow("HashAlgId", hex(metadata.assembly.hashAlgorithm, 8), "AssemblyHashAlgorithm value.") +
    renderDefinitionRow("PublicKey", metadata.assembly.publicKey == null ? "-" : `${metadata.assembly.publicKey.length} bytes`) +
    `</dl></details>`;
};

const renderTableStreamSummary = (metadata: PeClrMetadataTables): string =>
  `<details style="margin-top:.35rem"><summary>Metadata table stream</summary><dl>` +
  renderDefinitionRow("Stream", escapeHtml(metadata.streamName), "#~ is optimized; #- is unoptimized metadata tables.") +
  renderDefinitionRow("Version", `${metadata.majorVersion}.${metadata.minorVersion}`, "Metadata table stream version.") +
  renderDefinitionRow(
    "HeapSizes",
    `<div class="mono">${hex(metadata.heapSizes, 2)}</div>${renderFlagChips(metadata.heapSizes, METADATA_HEAP_FLAGS)}`,
    "String/GUID/Blob index-size flags plus CoreCLR metadata schema flags."
  ) +
  renderDefinitionRow("LargestRidLog2", hex(metadata.largestRidLog2, 2), "CoreCLR m_rid: log-base-2 of largest RID.") +
  (metadata.extraData == null
    ? ""
    : renderDefinitionRow("ExtraData", hex(metadata.extraData, 8), "Extra 4-byte CoreCLR schema value.")) +
  renderDefinitionRow("Index sizes", `${metadata.heapIndexSizes.string}/${metadata.heapIndexSizes.guid}/` +
    `${metadata.heapIndexSizes.blob} bytes`, "#Strings/#GUID/#Blob index widths.") +
  renderDefinitionRow("Valid", escapeHtml(metadata.validMask), "Bit mask of metadata tables present in the stream.") +
  renderDefinitionRow("Sorted", escapeHtml(metadata.sortedMask), "Bit mask of metadata tables sorted by key.") +
  `</dl></details>` +
  renderSimpleTable(
    "Metadata tables",
    ["Table", "Rows", "Sorted"],
    metadata.rowCounts.map(row => [
      escapeHtml(row.name),
      String(row.rows),
      row.sorted ? "Yes" : "No"
    ])
  );

const renderReferences = (metadata: PeClrMetadataTables): string =>
  renderSimpleTable(
    "Assembly references",
    ["Name", "Version", "Culture", "Flags"],
    metadata.assemblyRefs.map(row => [
      dash(row.name),
      escapeHtml(row.version),
      dash(row.culture),
      hex(row.flags, 8)
    ])
  ) +
  renderSimpleTable(
    "Type references",
    ["Type", "Resolution scope"],
    metadata.typeRefs.map(row => [dash(row.fullName), escapeHtml(indexText(row.resolutionScope))])
  );

const renderTypesAndMethods = (metadata: PeClrMetadataTables): string =>
  renderSimpleTable(
    "Type definitions",
    ["Type", "Extends", "Flags", "Methods"],
    metadata.typeDefs.map(row => [
      dash(row.fullName),
      escapeHtml(indexText(row.extends)),
      hex(row.flags, 8),
      methodCount(row)
    ])
  ) +
  renderSimpleTable(
    "Method definitions",
    ["Method", "RVA", "Flags", "Signature"],
    metadata.methodDefs.map(row => [
      escapeHtml(fullMethodName(row.ownerType, row.name)),
      hex(row.rva, 8),
      hex(row.flags, 4),
      escapeHtml(signatureText(row.signature))
    ])
  );

const renderCustomAttributes = (metadata: PeClrMetadataTables): string =>
  renderSimpleTable(
    "Custom attributes",
    ["Parent", "Attribute", "Constructor", "Arguments"],
    metadata.customAttributes.map(row => {
      const fixed = row.fixedArguments.map(arg => String(arg.value ?? "")).filter(Boolean);
      const named = row.namedArguments.map(arg => `${arg.name || "?"}=${String(arg.value ?? "")}`);
      return [
        dash(row.parentName || indexText(row.parent)),
        dash(row.attributeType),
        dash(row.constructorName),
        escapeHtml([...fixed, ...named].join("; ") || "-")
      ];
    })
  );

const renderManagedNativeAndResources = (metadata: PeClrMetadataTables): string =>
  renderSimpleTable(
    "P/Invoke map",
    ["Member", "Import", "Module", "Flags"],
    metadata.implMaps.map(row => [
      dash(row.memberName || indexText(row.member)),
      dash(row.importName),
      dash(row.importScopeName),
      hex(row.mappingFlags, 4)
    ])
  ) +
  renderSimpleTable(
    "Files and exported types",
    ["Kind", "Name", "Flags", "Implementation"],
    [
      ...metadata.files.map(row => ["File", dash(row.name), hex(row.flags, 8), "-"]),
      ...metadata.exportedTypes.map(row => [
        "ExportedType",
        dash(row.fullName),
        hex(row.flags, 8),
        escapeHtml(indexText(row.implementation))
      ])
    ]
  );

export const renderClrMetadataTables = (
  metadata: PeClrMetadataTables | undefined,
  out: string[]
): void => {
  if (!metadata) return;
  out.push(renderTargetFramework(metadata));
  out.push(renderAssembly(metadata));
  out.push(renderTableStreamSummary(metadata));
  out.push(renderReferences(metadata));
  out.push(renderTypesAndMethods(metadata));
  out.push(renderCustomAttributes(metadata));
  out.push(renderManagedNativeAndResources(metadata));
};
