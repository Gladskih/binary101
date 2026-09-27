"use strict";

// Numeric styles are transcribed from the Windows SDK WinUser.h:
// https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/WinUser.h
// Masked enum fields prevent composite values from acquiring overlapping flag names.
type StyleFlag = readonly [number, string];
type StyleField = { mask: number; values: readonly StyleFlag[] };

const windowFlags: readonly StyleFlag[] = [
  [0x80000000, "WS_POPUP"],
  [0x40000000, "WS_CHILD"],
  [0x20000000, "WS_MINIMIZE"],
  [0x10000000, "WS_VISIBLE"],
  [0x08000000, "WS_DISABLED"],
  [0x04000000, "WS_CLIPSIBLINGS"],
  [0x02000000, "WS_CLIPCHILDREN"],
  [0x01000000, "WS_MAXIMIZE"],
  [0x00800000, "WS_BORDER"],
  [0x00400000, "WS_DLGFRAME"],
  [0x00200000, "WS_VSCROLL"],
  [0x00100000, "WS_HSCROLL"],
  [0x00080000, "WS_SYSMENU"],
  [0x00040000, "WS_THICKFRAME"],
];

const dialogFlags: readonly StyleFlag[] = [
  [0x00000001, "DS_ABSALIGN"],
  [0x00000002, "DS_SYSMODAL"],
  [0x00000004, "DS_3DLOOK"],
  [0x00000008, "DS_FIXEDSYS"],
  [0x00000010, "DS_NOFAILCREATE"],
  [0x00000020, "DS_LOCALEDIT"],
  [0x00000040, "DS_SETFONT"],
  [0x00000080, "DS_MODALFRAME"],
  [0x00000100, "DS_NOIDLEMSG"],
  [0x00000200, "DS_SETFOREGROUND"],
  [0x00000400, "DS_CONTROL"],
  [0x00000800, "DS_CENTER"],
  [0x00001000, "DS_CENTERMOUSE"],
  [0x00002000, "DS_CONTEXTHELP"],
];

const extendedFlags: readonly StyleFlag[] = [
  [0x00000001, "WS_EX_DLGMODALFRAME"],
  [0x00000004, "WS_EX_NOPARENTNOTIFY"],
  [0x00000008, "WS_EX_TOPMOST"],
  [0x00000010, "WS_EX_ACCEPTFILES"],
  [0x00000020, "WS_EX_TRANSPARENT"],
  [0x00000040, "WS_EX_MDICHILD"],
  [0x00000080, "WS_EX_TOOLWINDOW"],
  [0x00000100, "WS_EX_WINDOWEDGE"],
  [0x00000200, "WS_EX_CLIENTEDGE"],
  [0x00000400, "WS_EX_CONTEXTHELP"],
  [0x00001000, "WS_EX_RIGHT"],
  [0x00002000, "WS_EX_RTLREADING"],
  [0x00004000, "WS_EX_LEFTSCROLLBAR"],
  [0x00010000, "WS_EX_CONTROLPARENT"],
  [0x00020000, "WS_EX_STATICEDGE"],
  [0x00040000, "WS_EX_APPWINDOW"],
  [0x00080000, "WS_EX_LAYERED"],
  [0x00100000, "WS_EX_NOINHERITLAYOUT"],
  [0x00200000, "WS_EX_NOREDIRECTIONBITMAP"],
  [0x00400000, "WS_EX_LAYOUTRTL"],
  [0x02000000, "WS_EX_COMPOSITED"],
  [0x08000000, "WS_EX_NOACTIVATE"],
];

const buttonFlags: readonly StyleFlag[] = [
  [0x00000020, "BS_LEFTTEXT"],
  [0x00000040, "BS_ICON"],
  [0x00000080, "BS_BITMAP"],
  [0x00001000, "BS_PUSHLIKE"],
  [0x00002000, "BS_MULTILINE"],
  [0x00004000, "BS_NOTIFY"],
  [0x00008000, "BS_FLAT"],
];

const editFlags: readonly StyleFlag[] = [
  [0x00000004, "ES_MULTILINE"],
  [0x00000008, "ES_UPPERCASE"],
  [0x00000010, "ES_LOWERCASE"],
  [0x00000020, "ES_PASSWORD"],
  [0x00000040, "ES_AUTOVSCROLL"],
  [0x00000080, "ES_AUTOHSCROLL"],
  [0x00000100, "ES_NOHIDESEL"],
  [0x00000400, "ES_OEMCONVERT"],
  [0x00000800, "ES_READONLY"],
  [0x00001000, "ES_WANTRETURN"],
  [0x00002000, "ES_NUMBER"],
];

const staticFlags: readonly StyleFlag[] = [
  [0x00000040, "SS_REALSIZECONTROL"],
  [0x00000080, "SS_NOPREFIX"],
  [0x00000100, "SS_NOTIFY"],
  [0x00000200, "SS_CENTERIMAGE"],
  [0x00000400, "SS_RIGHTJUST"],
  [0x00000800, "SS_REALSIZEIMAGE"],
  [0x00001000, "SS_SUNKEN"],
  [0x00002000, "SS_EDITCONTROL"],
];

const listFlags: readonly StyleFlag[] = [
  [0x00000001, "LBS_NOTIFY"],
  [0x00000002, "LBS_SORT"],
  [0x00000004, "LBS_NOREDRAW"],
  [0x00000008, "LBS_MULTIPLESEL"],
  [0x00000010, "LBS_OWNERDRAWFIXED"],
  [0x00000020, "LBS_OWNERDRAWVARIABLE"],
  [0x00000040, "LBS_HASSTRINGS"],
  [0x00000080, "LBS_USETABSTOPS"],
  [0x00000100, "LBS_NOINTEGRALHEIGHT"],
  [0x00000200, "LBS_MULTICOLUMN"],
  [0x00000400, "LBS_WANTKEYBOARDINPUT"],
  [0x00000800, "LBS_EXTENDEDSEL"],
  [0x00001000, "LBS_DISABLENOSCROLL"],
  [0x00002000, "LBS_NODATA"],
  [0x00004000, "LBS_NOSEL"],
  [0x00008000, "LBS_COMBOBOX"],
];

const comboFlags: readonly StyleFlag[] = [
  [0x00000010, "CBS_OWNERDRAWFIXED"],
  [0x00000020, "CBS_OWNERDRAWVARIABLE"],
  [0x00000040, "CBS_AUTOHSCROLL"],
  [0x00000080, "CBS_OEMCONVERT"],
  [0x00000100, "CBS_SORT"],
  [0x00000200, "CBS_HASSTRINGS"],
  [0x00000400, "CBS_NOINTEGRALHEIGHT"],
  [0x00000800, "CBS_DISABLENOSCROLL"],
  [0x00002000, "CBS_UPPERCASE"],
  [0x00004000, "CBS_LOWERCASE"],
];

const scrollFlags: readonly StyleFlag[] = [
  [0x00000001, "SBS_VERT"],
  [0x00000008, "SBS_SIZEBOX"],
  [0x00000010, "SBS_SIZEGRIP"],
];

const buttonFields: readonly StyleField[] = [
  { mask: 0xf, values: [
  [0x00000000, "BS_PUSHBUTTON"],
  [0x00000001, "BS_DEFPUSHBUTTON"],
  [0x00000002, "BS_CHECKBOX"],
  [0x00000003, "BS_AUTOCHECKBOX"],
  [0x00000004, "BS_RADIOBUTTON"],
  [0x00000005, "BS_3STATE"],
  [0x00000006, "BS_AUTO3STATE"],
  [0x00000007, "BS_GROUPBOX"],
  [0x00000008, "BS_USERBUTTON"],
  [0x00000009, "BS_AUTORADIOBUTTON"],
  [0x0000000a, "BS_PUSHBOX"],
  [0x0000000b, "BS_OWNERDRAW"],
  ] },
  { mask: 0x300, values: [
  [0x00000100, "BS_LEFT"],
  [0x00000200, "BS_RIGHT"],
  [0x00000300, "BS_CENTER"],
  ] },
  { mask: 0xc00, values: [
  [0x00000400, "BS_TOP"],
  [0x00000800, "BS_BOTTOM"],
  [0x00000c00, "BS_VCENTER"],
  ] },
];

const editFields: readonly StyleField[] = [
  { mask: 0x3, values: [
  [0x00000000, "ES_LEFT"],
  [0x00000001, "ES_CENTER"],
  [0x00000002, "ES_RIGHT"],
  ] },
];

const staticFields: readonly StyleField[] = [
  { mask: 0x1f, values: [
  [0x00000000, "SS_LEFT"],
  [0x00000001, "SS_CENTER"],
  [0x00000002, "SS_RIGHT"],
  [0x00000003, "SS_ICON"],
  [0x00000004, "SS_BLACKRECT"],
  [0x00000005, "SS_GRAYRECT"],
  [0x00000006, "SS_WHITERECT"],
  [0x00000007, "SS_BLACKFRAME"],
  [0x00000008, "SS_GRAYFRAME"],
  [0x00000009, "SS_WHITEFRAME"],
  [0x0000000a, "SS_USERITEM"],
  [0x0000000b, "SS_SIMPLE"],
  [0x0000000c, "SS_LEFTNOWORDWRAP"],
  [0x0000000d, "SS_OWNERDRAW"],
  [0x0000000e, "SS_BITMAP"],
  [0x0000000f, "SS_ENHMETAFILE"],
  [0x00000010, "SS_ETCHEDHORZ"],
  [0x00000011, "SS_ETCHEDVERT"],
  [0x00000012, "SS_ETCHEDFRAME"],
  ] },
  { mask: 0xc000, values: [
  [0x00004000, "SS_ENDELLIPSIS"],
  [0x00008000, "SS_PATHELLIPSIS"],
  [0x0000c000, "SS_WORDELLIPSIS"],
  ] },
];

const comboFields: readonly StyleField[] = [
  { mask: 0x3, values: [
  [0x00000001, "CBS_SIMPLE"],
  [0x00000002, "CBS_DROPDOWN"],
  [0x00000003, "CBS_DROPDOWNLIST"],
  ] },
];

const scrollFields: readonly StyleField[] = [
  { mask: 0x6, values: [
  [0x00000002, "SBS_TOPALIGN"],
  [0x00000004, "SBS_BOTTOMALIGN"],
  ] },
];

const hex = (value: number): string => `0x${(value >>> 0).toString(16).padStart(8, "0")}`;

const describeStyle = (
  value: number, flags: readonly StyleFlag[], fields: readonly StyleField[]
): string => {
  const names = flags.filter(([mask]) => (value & mask) !== 0).map(([, name]) => name);
  let known = flags.reduce((mask, [flag]) => mask | flag, 0);
  for (const field of fields) {
    const match = field.values.find(([option]) => (value & field.mask) === option);
    if (match) {
      names.push(match[1]);
      known |= field.mask;
    }
  }
  const unknown = (value & ~known) >>> 0;
  if (unknown) names.push(`unknown ${hex(unknown)}`);
  return `${hex(value)}${names.length ? ` (${names.join(" | ")})` : ""}`;
};

const commonFlags = (style: number): readonly StyleFlag[] => [
  ...windowFlags,
  [0x20000, style & 0x40000000 ? "WS_GROUP" : "WS_MINIMIZEBOX"],
  [0x10000, style & 0x40000000 ? "WS_TABSTOP" : "WS_MAXIMIZEBOX"]
];

export const formatDialogStyle = (style: number): string =>
  describeStyle(style, [...commonFlags(style), ...dialogFlags], []);

export const formatExtendedStyle = (style: number): string => describeStyle(style, extendedFlags, []);

export const formatControlStyle = (style: number, kind: string): string => {
  const schemes: Record<string, readonly [readonly StyleFlag[], readonly StyleField[]]> = {
    BUTTON: [buttonFlags, buttonFields], EDIT: [editFlags, editFields],
    STATIC: [staticFlags, staticFields], LISTBOX: [listFlags, []],
    COMBOBOX: [comboFlags, comboFields], SCROLLBAR: [scrollFlags, scrollFields]
  };
  const [flags, fields] = schemes[kind.toUpperCase()] ?? [[], []];
  return describeStyle(style, [...commonFlags(style), ...flags], fields);
};
