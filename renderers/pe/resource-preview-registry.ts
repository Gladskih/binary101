import type { ResourceLangWithPreview } from "../../analyzers/pe/resources/preview/types.js";
import { registryParameters } from "../../analyzers/pe/resources/preview/registry-parameters.js";
import { escapeHtml } from "../../html-utils.js";
import { renderAutoPagedSortableTable } from "../paged-sortable-table.js";
import { createRegistryTableModel } from "./resource-registry-table.js";

const renderParameters = (text: string): string => {
  const parameters = registryParameters(text, []);
  if (!parameters.length) return "";
  return `<p>Runtime replacement parameters: <span class="mono">` +
    `${parameters.map(name => escapeHtml(`%${name}%`)).join(", ")}</span>. ` +
    `Values remain symbolic; replacements may change the parsed structure. ` +
    `%% represents a literal percent sign.</p>`;
};

export const renderRegistryPreview = (
  entry: ResourceLangWithPreview | undefined, tableId = "pe-registry"
): string => {
  if (!entry?.registry) return "";
  const source = entry.textPreview;
  return `<p>ATL registry script. Root hives: ` +
    `${entry.registry.roots.map(root => escapeHtml(root.name)).join(", ") || "none"}. ` +
    `These are script declarations; registration depends on runtime parameters, permissions, ` +
    `registry state and the 32/64-bit view. ATL can redirect HKCR to per-user Classes. ` +
    `No registry changes are performed.</p>` +
    renderParameters(source ?? "") +
    `<p class="smallNote">ForceRemove/Delete respect ATL's protected key names, including ` +
    `CLSID, Interface, TypeLib, AppID and Software.</p>` +
    renderAutoPagedSortableTable(createRegistryTableModel(entry.registry, tableId)) +
    (source ? `<details><summary>RGS source (${escapeHtml(entry.textEncoding ?? "unknown")})</summary>` +
      `<pre class="mono">${escapeHtml(source)}</pre></details>` : "");
};
