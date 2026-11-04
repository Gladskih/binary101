"use strict";

import { indexResourceLeaves, resolveResourceReference, resourceAt } from "./resource-index.js";
import type { ResourceCatalog } from "./resource-index.js";
import type { ResourceDetailGroup, ResourceLangWithPreview } from "./preview/types.js";

export interface ResourceCrossCheck {
  status: "confirmed" | "warning" | "unresolved";
  subject: string;
  detail: string;
}

const label = (id: number | null, name: string | null, lang: number | null): string =>
  `${name ?? (id === null ? "(unnamed)" : `#${id}`)} / LANG ${lang ?? "neutral"}`;

const matchingDialog = (catalog: ResourceCatalog, key: number | string, lang: number | null) => {
  const resolution = resolveResourceReference(catalog, "DIALOG", key, lang);
  if (resolution.kind !== "exact" && resolution.kind !== "neutral") return null;
  const target = resourceAt(catalog, resolution.targets[0]!);
  return target?.dialogPreview ? target : null;
};

const checkDialogMenu = (menu: string | number | null, catalog: ResourceCatalog,
  lang: number | null, subject: string): ResourceCrossCheck | null => {
  if (menu === null) return null;
  const resolution = resolveResourceReference(catalog, "MENU", menu, lang);
  if (resolution.kind === "exact" || resolution.kind === "neutral") return {
    status: "confirmed", subject, detail: `DIALOG menu ${menu} matches an embedded MENU.` };
  if (resolution.kind === "missing") return { status: "warning", subject,
    detail: `DIALOG menu ${menu} has no matching embedded MENU; it may come from another module.` };
  return { status: "unresolved", subject, detail: `DIALOG menu ${menu} has ${resolution.kind} language variants; its target is unconfirmed.` };
};

const checkDialogInit = (
  init: NonNullable<ResourceLangWithPreview["dialogInit"]>,
  dialog: ResourceLangWithPreview, subject: string
): ResourceCrossCheck => {
  const controls = new Set(dialog.dialogPreview?.controls.map(control => control.id) ?? []);
  const missing = [...new Set(init.entries.map(entry => entry.controlId))]
    .filter(id => !controls.has(id));
  return missing.length
    ? { status: "warning", subject,
      detail: `DLGINIT references control IDs ${missing.join(", ")} absent from the matching DIALOG.` }
    : { status: "confirmed", subject,
      detail: `DLGINIT control IDs match the embedded DIALOG (${init.entries.length} records).` };
};

const checkDialogLayout = (
  layout: NonNullable<ResourceLangWithPreview["dialogLayout"]>,
  dialog: ResourceLangWithPreview, subject: string
): ResourceCrossCheck => {
  const controls = dialog.dialogPreview?.controls.length ?? 0;
  const count = layout.controls.length;
  return count === controls
    ? { status: "confirmed", subject,
      detail: `AFX_DIALOG_LAYOUT matches ${controls} DIALOG controls in child order.` }
    : { status: "warning", subject,
      detail: `AFX_DIALOG_LAYOUT has ${count} layout records for ${controls} DIALOG controls.` };
};

const checkMatchingDialog = (catalog: ResourceCatalog, type: string, key: string | number | null,
  lang: ResourceLangWithPreview, subject: string): ResourceCrossCheck[] => {
  const checks: ResourceCrossCheck[] = [];
      const dialog = key === null ? null : matchingDialog(catalog, key, lang.lang);
      if (type === "DLGINIT" && lang.dialogInit && dialog) {
        checks.push(checkDialogInit(lang.dialogInit, dialog, subject));
      }
      if (type === "AFX_DIALOG_LAYOUT" && lang.dialogLayout && dialog) {
        checks.push(checkDialogLayout(lang.dialogLayout, dialog, subject));
      }
  return checks;
};

export const collectResourceCrossChecks = (detail: ResourceDetailGroup[]): ResourceCrossCheck[] => {
  const catalog = indexResourceLeaves(detail);
  const checks: ResourceCrossCheck[] = [];
  for (const group of detail) for (const entry of group.entries) {
    for (const lang of entry.langs) {
      const subject = label(entry.id, entry.name, lang.lang);
      if (group.typeName === "DIALOG" && lang.dialogPreview) {
        const check = checkDialogMenu(lang.dialogPreview.menu, catalog, lang.lang, subject);
        if (check) checks.push(check);
      }
      checks.push(...checkMatchingDialog(catalog, group.typeName, entry.name ?? entry.id, lang, subject));
    }
  }
  return checks;
};
