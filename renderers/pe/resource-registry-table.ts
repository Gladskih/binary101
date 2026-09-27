import type {
  RegistryNode, RegistryScript, RegistryValue
} from "../../analyzers/pe/resources/preview/registry-types.js";
import { registryComRole } from "../../analyzers/pe/resources/preview/registry-analysis.js";
import { registryRootName } from "../../analyzers/pe/resources/preview/registry-parser.js";
import { escapeHtml } from "../../html-utils.js";
import type { PagedSortableTableModel } from "../paged-sortable-table.js";

interface RegistryRow {
  node: RegistryNode;
  parent: RegistryRow | null;
}

const indexes = new WeakMap<RegistryScript, RegistryRow[]>();

const registryRows = (script: RegistryScript): RegistryRow[] => {
  const cached = indexes.get(script);
  if (cached) return cached;
  const rows: RegistryRow[] = [];
  // Index parent links once for pagination. Do not retain a copied path per node:
  // that would require quadratic memory for deeply nested scripts.
  for (const node of script.roots) {
    const stack = [{ nodes: node.children, index: 0, parent: { node, parent: null } as RegistryRow }];
    while (stack.length) {
      const frame = stack[stack.length - 1]!;
      const child = frame.nodes[frame.index++];
      if (!child) { stack.pop(); continue; }
      const row = { node: child, parent: frame.parent };
      rows.push(row);
      if (child.children.length) stack.push({ nodes: child.children, index: 0, parent: row });
    }
  }
  indexes.set(script, rows);
  return rows;
};

const rowPath = (row: RegistryRow): string[] => {
  const path: string[] = [];
  let current: RegistryRow | null = row;
  while (current) {
    if (!current.parent) path.push(registryRootName(current.node.name) ?? current.node.name);
    else if (current.node.directive !== "val") path.push(current.node.name);
    current = current.parent;
  }
  return path.reverse();
};

const formatValue = (value: RegistryValue | null): string => {
  // Hex has 4 bits/digit: radix 2^4 = 16, byte width 8/4 = 2, DWORD width 32/4 = 8.
  // https://www.rfc-editor.org/rfc/rfc4648.html#section-8
  // https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types
  if (!value) return "—";
  switch (value.type) {
    case "REG_BINARY": return [...value.data].map(byte => byte.toString(16).padStart(2, "0")).join(" ");
    case "REG_MULTI_SZ": return value.data.map(part => JSON.stringify(part)).join("; ");
    case "REG_DWORD": return `${value.data} (0x${value.data.toString(16).padStart(8, "0")})`;
    case "unresolved": return `${value.source} (unresolved type ${value.tag})`;
    default: return value.data;
  }
};

const forcedDeletion = (name: string): string => {
  // CRegParser::rgszNeverDelete / CanForceRemoveKey applies to names at any depth.
  // https://github.com/adzm/atlmfc/blob/master/include/statreg.h
  return ["APPID", "CLSID", "COMPONENT CATEGORIES", "FILETYPE", "INTERFACE", "HARDWARE",
    "MIME", "SAM", "SECURITY", "SYSTEM", "SOFTWARE", "TYPELIB"].includes(name.toUpperCase())
    ? "Skip protected subtree deletion" : "Delete subtree";
};

const effects = (node: RegistryNode): [string, string] => {
  // Registration/unregistration branches in CRegParser::RegisterSubkeys:
  // https://github.com/adzm/atlmfc/blob/master/include/statreg.h
  switch (node.directive) {
    case "val": return ["Set named value", "Delete named value"];
    case "NoRemove": return ["Create/open key", "Keep key; process children"];
    case "ForceRemove": return [forcedDeletion(node.name) + "; create/open key",
      "Remove key after children, if no subkeys"];
    case "Delete": return [forcedDeletion(node.name), "Remove key after children, if no subkeys"];
    default: return ["Create/open key", "Remove key after children, if no subkeys"];
  }
};

const rowValues = (row: RegistryRow): string[] => {
  const path = rowPath(row);
  const node = row.node;
  return [path.join("\\"), node.directive,
    node.directive === "val" ? node.name || "(Default)" : node.value ? "(Default)" : "—",
    node.value?.type ?? "—", formatValue(node.value), registryComRole({ node, path }) ?? "—",
    ...effects(node), `${node.line}:${node.column}`];
};

export const createRegistryTableModel = (
  script: RegistryScript, tableId: string
): PagedSortableTableModel => {
  const rows = registryRows(script);
  return {
    // UI policy matching PE_RESOURCE_DETAIL_PAGE_SIZE in resources.ts, not an ATL/file limit.
    id: tableId, pageSize: 50, rowCount: rows.length,
    columns: ["Key path", "Directive", "Value name", "Type", "Data / template", "COM meaning",
      "Register", "Unregister", "Line:column"].map(label => ({ label })),
    rowAt: index => rows[index] ? {
      cells: rowValues(rows[index]).map(value => ({ html: escapeHtml(value), sortValue: value }))
    } : null,
    sortValueAt: (index, column) => rows[index] ? rowValues(rows[index])[column] ?? "" : "",
    tableClassName: "peResourceNestedTable"
  };
};
