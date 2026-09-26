import type {
  TypeLibraryAnalysis, TypeLibraryFunction, TypeLibraryType
} from "../../analyzers/pe/type-library/types.js";
import { escapeHtml } from "../../html-utils.js";
import {
  formatLibraryValue, formatTypeLibraryFlags, renderCustomData,
  renderTypeLibraryTable, resolveTypeLibraryDescription, resolveTypeLibraryReference
} from "./type-library-tables.js";

// Flags: Microsoft oaidl.h PARAMFLAG / FUNCFLAG / VARFLAG / IMPLTYPEFLAG.
// https://learn.microsoft.com/en-us/windows/win32/api/oaidl/
const renderFunction = (analysis: TypeLibraryAnalysis, member: TypeLibraryFunction): string => {
  return `<details><summary>${escapeHtml(
    ({ 1: "method", 2: "propget", 4: "propput", 8: "propputref" } as Record<number, string>)[member.invocation]
      ?? `INVOKEKIND(${member.invocation})`)} ${escapeHtml(member.name ?? "?")}(` +
    `${escapeHtml(member.parameters.map(parameter =>
      `${resolveTypeLibraryDescription(analysis, parameter.type)} ${parameter.name ?? "?"}`
    ).join(", "))}): ${escapeHtml(resolveTypeLibraryDescription(analysis, member.type))}` +
    `</summary>` + renderTypeLibraryTable("Function attributes", ["Attribute", "Value"], [
      ["DISPID / MEMBERID", `${member.id} (0x${(member.id >>> 0).toString(16)})`],
      ["Function kind", ["virtual", "pure virtual", "nonvirtual", "static", "dispatch"][member.kind]
        ?? member.kind],
      ["Calling convention", ["fastcall", "cdecl", "pascal", "macpascal", "stdcall",
        "reserved", "syscall", "mpwcdecl", "mpwpascal"][member.callingConvention]
        ?? member.callingConvention],
      ["Flags", formatTypeLibraryFlags(member.flags, ["restricted", "source", "bindable",
        "requestedit", "displaybind", "defaultbind", "hidden", "usesgetlasterror",
        "defaultcollelem", "uidefault", "nonbrowsable", "replaceable", "immediatebind"])],
      ["Vtable byte offset", member.vtableOffset], ["Optional parameters", member.optionalParameters],
      ["DLL entry", member.entry], ["Documentation", member.documentation],
      ["Help context", member.helpContext], ["Help string context", member.helpStringContext]
    ]) + renderTypeLibraryTable("Parameters", ["Name", "Type", "Flags", "Default value"],
      member.parameters.map(parameter => [parameter.name,
        resolveTypeLibraryDescription(analysis, parameter.type),
        formatTypeLibraryFlags(parameter.flags,
          ["in", "out", "lcid", "retval", "optional", "hasdefault", "hascustomdata"]),
        formatLibraryValue(parameter.defaultValue)])) + renderCustomData(member.customData) +
    member.parameters.map(parameter => parameter.customData.length
      ? `<p>Parameter ${escapeHtml(parameter.name ?? "?")}</p>${renderCustomData(parameter.customData)}`
      : "").join("") + `</details>`;
};

export const renderTypeLibraryMembers = (
  analysis: TypeLibraryAnalysis, type: TypeLibraryType
): string =>
  renderTypeLibraryTable("Implemented / inherited interfaces", ["Interface", "Flags"],
    type.interfaces.map(entry => [resolveTypeLibraryReference(analysis, entry.reference),
      formatTypeLibraryFlags(entry.flags, ["default", "source", "restricted", "defaultvtable"])])) +
  type.interfaces.map(entry => renderCustomData(entry.customData)).join("") +
  renderTypeLibraryTable("Variables / constants / fields", [
    "Name", "MEMBERID", "Type", "Kind", "Flags", "Value / byte offset", "Documentation", "Help context"
  ], type.variables.map(member => [member.name, member.id,
    resolveTypeLibraryDescription(analysis, member.type),
    ["per-instance", "static", "constant", "dispatch"][member.kind] ?? member.kind,
    formatTypeLibraryFlags(member.flags, ["readonly", "source", "bindable", "requestedit",
      "displaybind", "defaultbind", "hidden", "restricted", "defaultcollelem", "uidefault",
      "nonbrowsable", "replaceable", "immediatebind"]),
    member.instanceOffset ?? formatLibraryValue(member.value), member.documentation, member.helpContext])) +
  type.variables.map(member => renderCustomData(member.customData)).join("") +
  type.functions.map(member => renderFunction(analysis, member)).join("");
