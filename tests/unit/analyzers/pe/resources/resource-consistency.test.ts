import assert from "node:assert/strict";
import { test } from "node:test";
import { collectResourceCrossChecks } from "../../../../../analyzers/pe/resources/resource-consistency.js";
import type { ResourceDetailGroup, ResourceLangWithPreview } from
  "../../../../../analyzers/pe/resources/preview/types.js";

const leaf = (lang: number, preview: Partial<ResourceLangWithPreview>): ResourceLangWithPreview => ({
  lang, dataRVA: 1, size: 1, codePage: 0, dataFileOffset: 0, reserved: 0, ...preview
});
const dialog = (menu: string | null, controls: number[]) => leaf(1033, {
  dialogPreview: { helpId: null, templateKind: "standard", title: "Dialog", menu,
    className: null, x: 0, y: 0, width: 100, height: 100, style: 0, exStyle: 0,
    font: null, controls: controls.map(id => ({ id, kind: "BUTTON", title: null,
      x: 0, y: 0, width: 10, height: 10, style: 0, exStyle: 0 })) }
});
const group = (typeName: string, id: number, lang: ResourceLangWithPreview):
  ResourceDetailGroup => ({ typeName, entries: [{ id, name: null, langs: [lang] }] });

void test("confirms matching menu, dialog init, and layout references", () => {
  const detail = [group("DIALOG", 7, dialog("#9", [11, 12])),
    group("MENU", 9, leaf(1033, {})),
    group("DLGINIT", 7, leaf(1033, { dialogInit: { entries: [
      { controlId: 11, message: 0x401, data: new Uint8Array() }
    ] } })),
    group("AFX_DIALOG_LAYOUT", 7, leaf(1033, { dialogLayout: { version: 0,
      controls: [0, 1].map(() => ({ moveX: 0, moveY: 0, sizeX: 0, sizeY: 0 })) } }))];

  const checks = collectResourceCrossChecks(detail);

  assert.equal(checks.length, 3);
  assert.ok(checks.every(check => check.status === "confirmed"));
  assert.ok(checks.every(check => check.subject === "#7 / LANG 1033"));
  assert.match(checks.map(check => check.detail).join(" "), /MENU.*DLGINIT.*LAYOUT/su);
});

void test("reports only specific mismatches for matching dialog variants", () => {
  const detail = [group("DIALOG", 7, dialog("#9", [11])),
    group("DLGINIT", 7, leaf(1033, { dialogInit: { entries: [
      { controlId: 99, message: 0x401, data: new Uint8Array() },
      { controlId: 100, message: 0x401, data: new Uint8Array() }
    ] } })),
    group("AFX_DIALOG_LAYOUT", 7, leaf(1033, { dialogLayout: { version: 0,
      controls: [0, 1].map(() => ({ moveX: 0, moveY: 0, sizeX: 0, sizeY: 0 })) } }))];

  const checks = collectResourceCrossChecks(detail);

  assert.equal(checks.length, 3);
  assert.ok(checks.every(check => check.status === "warning"));
  assert.match(checks.map(check => check.detail).join(" "), /MENU.*99, 100.*2 layout/su);
});

void test("does not infer a relationship between different dialog languages or IDs", () => {
  const checks = collectResourceCrossChecks([
    group("DIALOG", 7, dialog(null, [11])),
    group("DLGINIT", 8, leaf(1033, { dialogInit: { entries: [
      { controlId: 99, message: 0x401, data: new Uint8Array() }
    ] } })),
    group("AFX_DIALOG_LAYOUT", 7, leaf(1041, { dialogLayout: { version: 0,
      controls: [] } }))
  ]);
  assert.deepEqual(checks, []);
});

void test("matches named menu keys without confusing them with numeric IDs", () => {
  const detail: ResourceDetailGroup[] = [group("DIALOG", 7, dialog("MAIN_MENU", [])),
    { typeName: "MENU", entries: [{ id: null, name: "MAIN_MENU", langs: [leaf(0, {})] }] }];
  assert.equal(collectResourceCrossChecks(detail)[0]?.status, "confirmed");
  assert.equal(collectResourceCrossChecks([group("DIALOG", 7, dialog("#9", [])),
    { typeName: "MENU", entries: [{ id: null, name: "#9", langs: [leaf(0, {})] }] }])[0]?.status,
  "warning");
});

void test("requires a complete numeric menu ordinal", () => {
  const cases = ["#9x", "x#9", "#99"];
  for (const menu of cases) {
    const checks = collectResourceCrossChecks([group("DIALOG", 7, dialog(menu, [])),
      group("MENU", 9, leaf(1033, {}))]);
    assert.equal(checks[0]?.status, "warning");
  }
});

void test("labels named and neutral resource variants accurately", () => {
  const detail: ResourceDetailGroup[] = [{ typeName: "DIALOG", entries: [
    { id: null, name: "Main", langs: [{ ...dialog("#9", []), lang: null }] },
    { id: null, name: null, langs: [{ ...dialog("#9", []), lang: null }] }
  ] }];
  const checks = collectResourceCrossChecks(detail);
  assert.equal(checks[0]?.subject, "Main / LANG neutral");
  assert.equal(checks[1]?.subject, "(unnamed) / LANG neutral");
});

void test("ignores unrelated preview fields on other resource kinds", () => {
  const unrelated = leaf(1033, { dialogPreview: dialog("#9", []).dialogPreview!,
    dialogInit: { entries: [] }, dialogLayout: { version: 0, controls: [] } });
  assert.deepEqual(collectResourceCrossChecks([
    group("DIALOG", 7, dialog(null, [])), group("RCDATA", 7, unrelated),
    group("DLGINIT", 7, leaf(1033, {})), group("AFX_DIALOG_LAYOUT", 7, leaf(1033, {}))
  ]), []);
});
