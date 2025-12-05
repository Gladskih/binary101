"use strict";

import { formatHumanSize, toHex32 } from "../../binary-utils.js";
import { escapeHtml, renderDefinitionRow } from "../../html-utils.js";
import type {
  SqliteLeafTableCell,
  SqlitePage,
  SqliteParseResult,
  SqliteRecordValue
} from "../../analyzers/sqlite/types.js";

const formatMaybe = (value: number | null | undefined, suffix = ""): string =>
  value == null ? "Unknown" : `${value}${suffix}`;

const valueWithMeaning = (
  value: number | string | bigint | null | undefined,
  meaning: string | null | undefined,
  suffix = ""
): string => {
  if (value == null) return "Unknown";
  const text = typeof value === "bigint" ? value.toString() : String(value);
  if (!meaning) return `${escapeHtml(text)}${suffix}`;
  return `${escapeHtml(text)}${suffix} (${escapeHtml(meaning)})`;
};

const renderIssues = (issues: string[]): string => {
  if (!issues.length) return "";
  const items = issues.map(issue => `<li>${escapeHtml(issue)}</li>`).join("");
  return `<h4>Warnings</h4><ul class="issueList">${items}</ul>`;
};

const renderHeader = (parsed: SqliteParseResult): string => {
  const header = parsed.header;
  const rows = [
    renderDefinitionRow(
      "Page size",
      formatMaybe(header.pageSizeBytes, " bytes"),
      "Number of bytes per b-tree page (1 represents 65536)."
    ),
    renderDefinitionRow(
      "Usable page size",
      formatMaybe(header.usablePageSize, " bytes"),
      "Page size minus reserved bytes; affects payload capacity."
    ),
    renderDefinitionRow(
      "Reserved bytes",
      formatMaybe(header.reservedSpace, " bytes"),
      "Bytes left unused at the end of each page for extensions like checksums."
    ),
    renderDefinitionRow(
      "Write version",
      valueWithMeaning(header.writeVersion, header.writeVersionMeaning),
      "Journal mode required for writers (1=rollback journal, 2=WAL)."
    ),
    renderDefinitionRow(
      "Read version",
      valueWithMeaning(header.readVersion, header.readVersionMeaning),
      "Minimum journal mode readers expect (1=rollback journal, 2=WAL)."
    ),
    renderDefinitionRow(
      "Payload fractions",
      [
        formatMaybe(header.maxPayloadFraction),
        formatMaybe(header.minPayloadFraction),
        formatMaybe(header.leafPayloadFraction)
      ].join(" / "),
      [
        "Maximum embedded payload, minimum embedded payload, and leaf payload fractions",
        "(defaults 64/32/32)."
      ].join(" ")
    ),
    renderDefinitionRow(
      "Change counter",
      formatMaybe(header.fileChangeCounter),
      "Incremented when the database content changes."
    ),
    renderDefinitionRow(
      "Database size",
      header.databaseSizeBytes != null
        ? `${formatHumanSize(header.databaseSizeBytes)}`
        : formatMaybe(header.databaseSizePages, " pages"),
      "Number of pages in the database file."
    ),
    renderDefinitionRow(
      "Freelist",
      [
        `${formatMaybe(header.firstFreelistTrunkPage)} (first trunk)`,
        `${formatMaybe(header.totalFreelistPages)} (total pages)`
      ].join(" / "),
      "Tracks unused pages that can be recycled."
    ),
    renderDefinitionRow(
      "Schema cookie",
      formatMaybe(header.schemaCookie),
      "Schema version used to detect DDL changes."
    ),
    renderDefinitionRow(
      "Schema format",
      valueWithMeaning(header.schemaFormat, header.schemaFormatMeaning),
      "File-format revision; must be between 1 and 4."
    ),
    renderDefinitionRow(
      "Default page cache size",
      formatMaybe(header.defaultPageCacheSize, " pages"),
      "Preferred cache size when unspecified by the host."
    ),
    renderDefinitionRow(
      "Largest root page",
      formatMaybe(header.largestRootPage),
      "Largest root b-tree page number (historical field)."
    ),
    renderDefinitionRow(
      "Text encoding",
      valueWithMeaning(header.textEncodingName, null),
      "Encoding used for text values in records."
    ),
    renderDefinitionRow(
      "User version",
      formatMaybe(header.userVersion),
      "Application-defined schema marker."
    ),
    renderDefinitionRow(
      "Auto-vacuum",
      valueWithMeaning(header.vacuumMode, header.vacuumModeMeaning),
      "0 disables auto-vacuum, 1 enables full, 2 enables incremental."
    ),
    renderDefinitionRow(
      "Application ID",
      header.applicationId != null ? toHex32(header.applicationId, 8) : "Unknown",
      "Identifier set by applications to tag the file."
    ),
    renderDefinitionRow(
      "Version-valid-for",
      formatMaybe(header.versionValidFor),
      "Change counter value when the cache was last valid (WAL housekeeping)."
    ),
    renderDefinitionRow(
      "SQLite version",
      valueWithMeaning(header.sqliteVersionString, null),
      "SQLite library version that last wrote the file."
    )
  ];
  return `<h4>File header</h4><dl>${rows.join("")}</dl>`;
};

const formatRowId = (rowId: bigint | null): string =>
  rowId == null ? "Unknown" : rowId.toString();

const valueByName = (values: SqliteRecordValue[], name: string): SqliteRecordValue | undefined =>
  values.find(value => value.name === name);

const renderCellNote = (cell: SqliteLeafTableCell): string => {
  const payloadText =
    cell.payloadSize == null
      ? "unknown payload"
      : `${cell.payloadSize} bytes (${cell.payloadAvailable} in page)`;
  const recordNote = cell.record.headerTruncated ? "header truncated" : "record header ok";
  const overflowNote = cell.overflow ? "needs overflow pages" : "fits in page";
  return `${payloadText}; ${recordNote}; ${overflowNote}`;
};

const renderSchemaEntries = (schemaPage: SqlitePage | null | undefined): string => {
  if (!schemaPage || !schemaPage.cells.length) {
    return '<p class="dim">No schema entries were parsed from page 1.</p>';
  }
  const rows = schemaPage.cells
    .map(cell => {
      const values = cell.record.values;
      const type = valueByName(values, "type")?.value ?? "-";
      const name = valueByName(values, "name")?.value ?? "-";
      const tableName = valueByName(values, "tbl_name")?.value ?? "-";
      const rootPage = valueByName(values, "rootpage")?.value ?? "-";
      const sql = valueByName(values, "sql")?.value ?? "-";
      return [
        "<tr>",
        `<td>${formatRowId(cell.rowId)}</td>`,
        `<td>${escapeHtml(type ?? "-")}</td>`,
        `<td>${escapeHtml(name ?? "-")}</td>`,
        `<td>${escapeHtml(tableName ?? "-")}</td>`,
        `<td>${escapeHtml(String(rootPage))}</td>`,
        `<td title="${escapeHtml(renderCellNote(cell))}">${escapeHtml(String(sql))}</td>`,
        "</tr>"
      ].join("");
    })
    .join("");
  const notes = schemaPage.limitedByCellCount
    ? [
        "<div class=\"smallNote\">Only the first ",
        schemaPage.cells.length,
        " of ",
        schemaPage.header?.cellCount,
        " cells are shown.</div>"
      ].join("")
    : "";
  return [
    "<h4>Schema entries (sqlite_schema)</h4>",
    [
      '<table class="byteView"><thead><tr><th>rowid</th><th>Type</th><th>Name</th><th>Table</th>',
      "<th>Root page</th><th>SQL</th></tr></thead>"
    ].join(""),
    `<tbody>${rows}</tbody></table>`,
    notes
  ].join("");
};

const renderPageHeader = (schemaPage: SqlitePage | null | undefined): string => {
  if (!schemaPage || !schemaPage.header) return "";
  const header = schemaPage.header;
  const rows = [
    renderDefinitionRow(
      "Page type",
      valueWithMeaning(header.pageType, header.pageTypeMeaning),
      "Identifies whether this is a table or index page."
    ),
    renderDefinitionRow(
      "Cell count",
      formatMaybe(header.cellCount),
      "Number of cells stored on the page."
    ),
    renderDefinitionRow(
      "First freeblock",
      formatMaybe(header.firstFreeblock),
      "Offset to the first free block within the page."
    ),
    renderDefinitionRow(
      "Cell content start",
      formatMaybe(header.cellContentStart, " bytes"),
      "Offset where cell payloads start (grows downward)."
    ),
    renderDefinitionRow(
      "Fragmented bytes",
      formatMaybe(header.fragmentedFreeBytes, " bytes"),
      "Bytes of fragmented free space within the page."
    ),
    renderDefinitionRow(
      "Right-most pointer",
      header.rightMostPointer != null ? formatMaybe(header.rightMostPointer) : "Not present",
      "Only used on interior pages."
    )
  ];
  return `<h4>Schema b-tree page</h4><dl>${rows.join("")}</dl>`;
};

const renderSqlite = (parsedInput: SqliteParseResult | null | unknown): string => {
  const parsed = parsedInput as SqliteParseResult | null;
  if (!parsed) return "";
  const out: string[] = [];
  out.push("<h3>SQLite database</h3>");
  out.push(renderHeader(parsed));
  out.push(renderPageHeader(parsed.schemaPage));
  out.push(renderSchemaEntries(parsed.schemaPage));
  out.push(renderIssues(parsed.issues || []));
  return out.join("");
};

export { renderSqlite };
