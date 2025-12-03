"use strict";

const LINK_FLAGS: Array<[number, string, string?]> = [
  [0x00000001, "Has ID list", "LinkTargetIDList present"],
  [0x00000002, "Has LinkInfo", "LinkInfo structure present"],
  [0x00000004, "Has name"],
  [0x00000008, "Has relative path"],
  [0x00000010, "Has working dir"],
  [0x00000020, "Has arguments"],
  [0x00000040, "Has icon location"],
  [0x00000080, "Unicode strings"],
  [0x00000100, "Force no LinkInfo"],
  [0x00000200, "Has environment path"],
  [0x00000400, "Run separately"],
  [0x00001000, "Has Darwin ID"],
  [0x00002000, "Run as different user"],
  [0x00004000, "Has expanded icon"],
  [0x00008000, "No PIDL alias"],
  [0x00020000, "Shim layer"],
  [0x00080000, "Enable metadata"],
  [0x02000000, "Prefer environment path"]
];

const FILE_ATTRIBUTE_FLAGS: Array<[number, string, string?]> = [
  [0x00000001, "Read-only"],
  [0x00000002, "Hidden"],
  [0x00000004, "System"],
  [0x00000010, "Directory"],
  [0x00000020, "Archive"],
  [0x00000040, "Device"],
  [0x00000080, "Normal"],
  [0x00000100, "Temporary"],
  [0x00000200, "Sparse"],
  [0x00000400, "Reparse point"],
  [0x00000800, "Compressed"],
  [0x00001000, "Offline"],
  [0x00002000, "Not indexed"],
  [0x00004000, "Encrypted"],
  [0x00008000, "Integrity stream"],
  [0x00010000, "Virtual"],
  [0x00020000, "No scrub data"]
];

const LINKINFO_FLAGS: Array<[number, string, string?]> = [
  [0x00000001, "Volume ID + local base"],
  [0x00000002, "Network relative link"]
];

const SHOW_COMMAND_OPTIONS: Array<[number, string]> = [
  [1, "Normal window"],
  [3, "Maximized"],
  [7, "Minimized"]
];

export { FILE_ATTRIBUTE_FLAGS, LINKINFO_FLAGS, LINK_FLAGS, SHOW_COMMAND_OPTIONS };
