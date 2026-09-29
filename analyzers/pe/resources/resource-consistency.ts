"use strict";

import type { ResourceDetailGroup, ResourceLangWithPreview } from "./preview/types.js";

export interface ResourceCrossCheck {
  status: "confirmed" | "warning";
  subject: string;
  detail: string;
}

const identity = (id: number | null, name: string | null, lang: number | null): string =>
  JSON.stringify([id, name, lang]);
const label = (id: number | null, name: string | null, lang: number | null): string =>
  `${name ?? (id === null ? "(unnamed)" : `#${id}`)} / LANG ${lang ?? "neutral"}`;
const matchingDialog = (dialogs: Map<string, ResourceLangWithPreview>,
  id: number | null, name: string | null, lang: number | null): ResourceLangWithPreview | null =>
  dialogs.get(identity(id, name, lang)) ?? null;

const checkDialogMenu = (
  menu: string | null, menus: Set<string>, subject: string
): ResourceCrossCheck | null => {
  if (!menu) return null;
  // DLG template menu ordinals are rendered as #<WORD> by readDialogField.
  // https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-dlgtemplate
  const key = /^#\d+$/u.test(menu) ? identity(Number(menu.slice(1)), null, null)
    : identity(null, menu, null);
  return menus.has(key)
    ? { status: "confirmed", subject, detail: `DIALOG menu ${menu} matches an embedded MENU.` }
    : { status: "warning", subject,
      detail: `DIALOG menu ${menu} has no matching embedded MENU; it may come from another module.` };
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

export const collectResourceCrossChecks = (detail: ResourceDetailGroup[]): ResourceCrossCheck[] => {
  const dialogs = new Map<string, ResourceLangWithPreview>();
  const menus = new Set<string>();
  for (const group of detail) {
    if (group.typeName !== "DIALOG" && group.typeName !== "MENU") continue;
    for (const entry of group.entries) {
      if (group.typeName === "MENU") {
        menus.add(identity(entry.id, entry.name, null));
      } else for (const lang of entry.langs) {
        if (lang.dialogPreview) dialogs.set(identity(entry.id, entry.name, lang.lang), lang);
      }
    }
  }
  const checks: ResourceCrossCheck[] = [];
  for (const group of detail) for (const entry of group.entries) {
    for (const lang of entry.langs) {
      const subject = label(entry.id, entry.name, lang.lang);
      if (group.typeName === "DIALOG" && lang.dialogPreview) {
        const check = checkDialogMenu(lang.dialogPreview.menu, menus, subject);
        if (check) checks.push(check);
      }
      const dialog = matchingDialog(dialogs, entry.id, entry.name, lang.lang);
      if (group.typeName === "DLGINIT" && lang.dialogInit && dialog) {
        checks.push(checkDialogInit(lang.dialogInit, dialog, subject));
      }
      if (group.typeName === "AFX_DIALOG_LAYOUT" && lang.dialogLayout && dialog) {
        checks.push(checkDialogLayout(lang.dialogLayout, dialog, subject));
      }
    }
  }
  return checks;
};
