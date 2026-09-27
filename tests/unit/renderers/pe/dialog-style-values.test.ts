import assert from "node:assert/strict";
import { test } from "node:test";
import { formatDialogStyle, formatControlStyle, formatExtendedStyle } from "../../../../renderers/pe/dialog-style-values.js";

void test("decodes dialog and class-specific control styles without overlapping enum flags", () => {
  assert.match(formatDialogStyle(0x90c00048), /WS_POPUP.*WS_VISIBLE.*WS_BORDER.*WS_DLGFRAME.*DS_FIXEDSYS.*DS_SETFONT/);
  assert.match(formatControlStyle(0x50010301, "BUTTON"), /WS_CHILD.*WS_VISIBLE.*WS_TABSTOP.*BS_DEFPUSHBUTTON.*BS_CENTER/);
  assert.doesNotMatch(formatControlStyle(0x301, "BUTTON"), /BS_LEFT\b|BS_RIGHT\b/);
  assert.match(formatControlStyle(0x804, "EDIT"), /ES_MULTILINE.*ES_READONLY.*ES_LEFT/);
  assert.match(formatControlStyle(0xc003, "STATIC"), /SS_ICON.*SS_WORDELLIPSIS/);
  assert.doesNotMatch(formatControlStyle(0xc003, "STATIC"), /SS_ENDELLIPSIS|SS_PATHELLIPSIS/);
  assert.match(formatControlStyle(3, "COMBOBOX"), /CBS_DROPDOWNLIST/);
  assert.match(formatControlStyle(0x100, "LISTBOX"), /LBS_NOINTEGRALHEIGHT/);
  assert.match(formatControlStyle(1, "SCROLLBAR"), /SBS_VERT/);
});

void test("preserves unknown bits and formats unsigned styles and extended styles", () => {
  assert.match(formatControlStyle(0x80000080, "custom"), /0x80000080.*unknown 0x00000080/);
  assert.match(formatExtendedStyle(0x208), /WS_EX_TOPMOST.*WS_EX_CLIENTEDGE/);
  assert.match(formatExtendedStyle(0x80000000), /unknown 0x80000000/);
  assert.equal(formatExtendedStyle(0), "0x00000000");
});
