"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  formatOperatingSystemVersion,
  formatSubsystemVersion,
  renderHeaderVersions
} from "../../../../renderers/pe/header-versions.js";
import type { PeWindowsOptionalHeader } from "../../../../analyzers/pe/types.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";

// Independent expected product names from Microsoft's OS version tables:
// https://learn.microsoft.com/en-us/windows/win32/sysinfo/operating-system-version
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoexa
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rap/187b8ded-16d0-4c17-9a75-c7b47795df93
// https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info
const windowsVersions: Array<[number, number, string]> = [
  // Chappell's kernel-version study and Wine's VersionData distinguish 3.10/3.50/3.51.
  [3, 10, "Windows NT 3.1"],
  [3, 50, "Windows NT 3.5"],
  [3, 51, "Windows NT 3.51"],
  [4, 0, "Windows NT 4.0 / Windows 95"],
  [4, 10, "Windows 98 / Windows 98 Second Edition"],
  [4, 90, "Windows Me"],
  [5, 0, "Windows 2000"],
  // MS04-016 lists separate 5.1 and 5.2 Itanium XP update payloads.
  [5, 1, "Windows XP / Windows XP 64-Bit Edition (Itanium)"],
  [5, 2, "Windows XP Professional x64 Edition / " +
    "Windows XP 64-Bit Edition Version 2003 (Itanium) / Windows Server 2003 / " +
    "Windows Server 2003 R2 / Windows Home Server"],
  [6, 0, "Windows Vista / Windows Server 2008"],
  [6, 1, "Windows 7 / Windows Server 2008 R2 / Windows Home Server 2011"],
  [6, 2, "Windows 8 / Windows Server 2012 / Windows RT"],
  [6, 3, "Windows 8.1 / Windows Server 2012 R2 / Windows RT 8.1"],
  [10, 0, "Windows 10 / Windows 11 / Windows Server 2016 / Windows Server 2019 / " +
    "Windows Server 2022 / Windows Server 2025"]
];

for (const [major, minor, names] of windowsVersions) {
  void test(`explains Windows version ${major}.${minor} without losing the numeric pair`, () => {
    assert.equal(formatOperatingSystemVersion(major, minor, 3), `${major}.${minor} (${names})`);
  });
}

const unmappedVersions: Array<[number, number]> = [
  [0, 0], [11, 0], [6, 10], [65535, 65535], [-1, 0], [3, 1], [3, 5], [6, 30]
];

for (const [major, minor] of unmappedVersions) {
  void test(`preserves unmapped OS version ${major}.${minor} without duplication`, () => {
    assert.equal(formatOperatingSystemVersion(major, minor, 3), `${major}.${minor}`);
  });
}

void test("includes Win32s only in the Windows GUI version context", () => {
  // Wine's WIN31 version entry is 3.10 / VER_PLATFORM_WIN32s;
  // OS/2 Museum's NT 3.1 porting experiment uses subsystem 3.10 and also runs on Win32s.
  assert.equal(formatOperatingSystemVersion(3, 10, 2),
    "3.10 (Windows NT 3.1 / Windows 3.1 with Win32s)");
  assert.equal(formatSubsystemVersion(3, 10, 2),
    "3.10 (Windows GUI subsystem; Windows NT 3.1 / Windows 3.1 with Win32s)");
  assert.equal(formatSubsystemVersion(3, 10, 3), "3.10 (Windows CUI subsystem; Windows NT 3.1)");
});

void test("interprets the documented CeGCC 4.20 target in the CE namespace", () => {
  // https://cegcc.sourceforge.net/docs/details.html: major=4, minor=20 targets CE 4.20.
  assert.equal(formatSubsystemVersion(4, 20, 9),
    "4.20 (Windows CE GUI subsystem; Windows CE .NET 4.2)");
  assert.equal(formatSubsystemVersion(4, 20, 2), "4.20 (Windows GUI subsystem)");
});

void test("keeps Windows CE OS versions separate from desktop Windows", () => {
  // Microsoft PE format: 9 = IMAGE_SUBSYSTEM_WINDOWS_CE_GUI.
  assert.equal(formatOperatingSystemVersion(4, 0, 9), "4.0 (Windows CE)");
});

for (const subsystem of [10, 11, 12, 13]) {
  void test(`does not identify firmware OS fields as Windows for subsystem ${subsystem}`, () => {
    // Microsoft PE format: EFI subsystems 10-13; EDK II GenFw zeros OS versions.
    assert.equal(formatOperatingSystemVersion(6, 1, subsystem), "6.1");
    assert.equal(formatOperatingSystemVersion(0, 0, subsystem), "0.0");
  });
}

// Subsystem IDs and version semantics: Microsoft PE format / Windows Subsystem,
// https://learn.microsoft.com/en-us/cpp/build/reference/subsystem-specify-subsystem
const subsystemVersions: Array<[number, number, number, string]> = [
  [6, 1, 2, "6.1 (Windows GUI subsystem; Windows 7 / Windows Server 2008 R2 / " +
    "Windows Home Server 2011)"],
  [6, 1, 3, "6.1 (Windows CUI subsystem; Windows 7 / Windows Server 2008 R2 / " +
    "Windows Home Server 2011)"],
  [6, 10, 2, "6.10 (Windows GUI subsystem)"],
  [0, 0, 3, "0.0 (Windows CUI subsystem)"],
  [1, 10, 1, "1.10 (Native subsystem; driver/system-process version, not a Windows release)"],
  [6, 1, 1, "6.1 (Native subsystem; driver/system-process version, not a Windows release)"],
  [6, 1, 5, "6.1 (OS/2 CUI subsystem)"],
  [6, 1, 7, "6.1 (POSIX CUI subsystem)"],
  [4, 0, 8, "4.0 (Native Windows subsystem; Win9x driver)"],
  [6, 1, 9, "6.1 (Windows CE GUI subsystem)"],
  [1, 0, 10, "1.0 (EFI Application subsystem; not a UEFI specification revision)"],
  [0, 0, 11, "0.0 (EFI Boot Service Driver subsystem; not a UEFI specification revision)"],
  [6, 1, 12, "6.1 (EFI Runtime Driver subsystem; not a UEFI specification revision)"],
  [2, 0, 13, "2.0 (EFI ROM subsystem; not a UEFI specification revision)"],
  [6, 1, 14, "6.1 (XBOX subsystem)"],
  [1, 0, 16, "1.0 (Windows Boot Application subsystem)"],
  [6, 1, 0, "6.1 (Unknown subsystem 0)"],
  [65535, 65535, 65535, "65535.65535 (Unknown subsystem 65535)"]
];

for (const [major, minor, subsystem, expected] of subsystemVersions) {
  void test(`explains subsystem ${subsystem} version ${major}.${minor} in its own context`, () => {
    assert.equal(formatSubsystemVersion(major, minor, subsystem), expected);
  });
}

void test("renderHeaderVersions explains each version field using its own values and subsystem", () => {
  const optionalHeader = createBasePe().opt as PeWindowsOptionalHeader;
  // Microsoft PE format: subsystem 3 is Windows CUI; OS 6.1 is Windows 7 / Server 2008 R2.
  optionalHeader.OSVersionMajor = 6;
  optionalHeader.OSVersionMinor = 1;
  optionalHeader.ImageVersionMajor = 7;
  optionalHeader.ImageVersionMinor = 8;
  optionalHeader.SubsystemVersionMajor = 5;
  optionalHeader.SubsystemVersionMinor = 2;
  optionalHeader.Subsystem = 3;
  const html = renderHeaderVersions(optionalHeader);
  assert.ok(html.includes(
    `>OperatingSystemVersion</dt><dd>6.1 (Windows 7 / Windows Server 2008 R2 / ` +
    `Windows Home Server 2011)</dd>`
  ));
  assert.ok(html.includes(`>ImageVersion</dt><dd>7.8</dd>`));
  assert.ok(html.includes(
    `>SubsystemVersion</dt><dd>5.2 (Windows CUI subsystem; ` +
    `Windows XP Professional x64 Edition / Windows XP 64-Bit Edition Version 2003 (Itanium) / ` +
    `Windows Server 2003 / ` +
    `Windows Server 2003 R2 / Windows Home Server)</dd>`
  ));
  assert.ok(html.includes(
    `title="Declared required OS version. Names identify version families, not proven compatibility."`
  ));
  assert.ok(html.includes(
    `title="Author-defined image version; separate from file/product version resources."`
  ));
  assert.ok(html.includes(
    `title="Minimum version of the selected subsystem; not necessarily a Windows release number."`
  ));
});
