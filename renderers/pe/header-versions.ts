"use strict";

import { SUBSYSTEMS } from "../../analyzers/pe/constants.js";
import type { PeWindowsOptionalHeader } from "../../analyzers/pe/types.js";
import { renderDefinitionRow } from "../../html-utils.js";

// Known product-family correspondences, not an exhaustive SKU or compatibility list.
// Source audit and deliberate limits: docs/pe-header-versions.md.
// https://learn.microsoft.com/en-us/windows/win32/sysinfo/operating-system-version
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoexa
// Historical Win9x version pairs:
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rap/187b8ded-16d0-4c17-9a75-c7b47795df93
// Server 2025 shares the 10.0 family (build 26100):
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/e81cbc09-ab05-4a32-ae4a-8ec57b436c43
const WINDOWS_VERSIONS = new Map<string, string>([
  // Historical NT names/numbers and Win32s: Chappell's inspected binaries and Wine VersionData.
  // https://www.geoffchappell.com/studies/windows/km/versions.htm
  // https://github.com/wine-mirror/wine/blob/c42c1532a8b8a767d5e23b527ea874368c202ed0/dlls/ntdll/version.c
  ["3.10", "Windows NT 3.1"],
  ["3.50", "Windows NT 3.5"],
  ["3.51", "Windows NT 3.51"],
  ["4.0", "Windows NT 4.0 / Windows 95"],
  ["4.10", "Windows 98 / Windows 98 Second Edition"],
  ["4.90", "Windows Me"],
  ["5.0", "Windows 2000"],
  // MS04-016 documents the 5.1/5.2 Itanium XP branches separately from XP Professional x64.
  // https://learn.microsoft.com/en-us/security-updates/securitybulletins/2004/ms04-016
  ["5.1", "Windows XP / Windows XP 64-Bit Edition (Itanium)"],
  ["5.2", "Windows XP Professional x64 Edition / " +
    "Windows XP 64-Bit Edition Version 2003 (Itanium) / Windows Server 2003 / " +
    "Windows Server 2003 R2 / Windows Home Server"],
  ["6.0", "Windows Vista / Windows Server 2008"],
  // Home Server 2011 uses the Server 2008 R2 base; RT's 6.2/6.3 observations are linked in the audit.
  // https://learn.microsoft.com/en-us/windows/win32/srvnodes/windows-server
  ["6.1", "Windows 7 / Windows Server 2008 R2 / Windows Home Server 2011"],
  ["6.2", "Windows 8 / Windows Server 2012 / Windows RT"],
  ["6.3", "Windows 8.1 / Windows Server 2012 R2 / Windows RT 8.1"],
  ["10.0", "Windows 10 / Windows 11 / Windows Server 2016 / Windows Server 2019 / " +
    "Windows Server 2022 / Windows Server 2025"]
]);

const windowsVersionNames = (version: string, subsystem: number): string | undefined => {
  const names = WINDOWS_VERSIONS.get(version);
  // Win32s supports Windows 3.1 GUI applications, not the NT console subsystem.
  // https://www.os2museum.com/wp/retro-porting-to-nt-3-1/
  return version === "3.10" && subsystem === 2
    ? `${names} / Windows 3.1 with Win32s`
    : names;
};

export const formatOperatingSystemVersion = (
  major: number,
  minor: number,
  subsystem: number
): string => {
  const version = `${major}.${minor}`;
  // The Windows CE and EFI subsystem IDs are defined in Microsoft PE format.
  // CE uses its own OS versions; EFI OS fields do not identify desktop Windows.
  if (subsystem === 9) return `${version} (Windows CE)`;
  if ([10, 11, 12, 13].includes(subsystem)) return version;
  const names = windowsVersionNames(version, subsystem);
  return names ? `${version} (${names})` : version;
};

const subsystemVersionNames = (version: string, subsystem: number): string | undefined => {
  // CeGCC documents the exact pair 4/20; LXE's device manual calls this CE .NET 4.2.
  // https://cegcc.sourceforge.net/docs/details.html
  // https://www.manualslib.com/manual/290367/Lxe-Mx3x.html?page=323
  if (subsystem === 9) return version === "4.20" ? "Windows CE .NET 4.2" : undefined;
  if ([2, 3].includes(subsystem)) return windowsVersionNames(version, subsystem);
  return undefined;
};

const subsystemVersionMeaning = (version: string, subsystem: number): string => {
  const label = SUBSYSTEMS.find(([code]) => code === subsystem)?.[1];
  if (!label || subsystem === 0) return `Unknown subsystem ${subsystem}`;
  // Microsoft /SUBSYSTEM: only GUI/CUI use the desktop Windows version mapping.
  // NATIVE WDM versions (e.g. 1.10) are not Windows release numbers.
  // https://learn.microsoft.com/en-us/cpp/build/reference/subsystem-specify-subsystem
  const names = subsystemVersionNames(version, subsystem);
  if (names) return `${label} subsystem; ${names}`;
  if (subsystem === 1) {
    return `${label} subsystem; driver/system-process version, not a Windows release`;
  }
  if (subsystem === 8) return `${label} subsystem; Win9x driver`;
  // EDK II GenFw normally zeros these fields in firmware images. Do not infer
  // a UEFI specification revision from a producer's PE subsystem version.
  // https://github.com/tianocore/edk2/blob/master/BaseTools/Source/C/GenFw/GenFw.c
  if ([10, 11, 12, 13].includes(subsystem)) {
    return `${label} subsystem; not a UEFI specification revision`;
  }
  return `${label} subsystem`;
};

export const formatSubsystemVersion = (
  major: number,
  minor: number,
  subsystem: number
): string => `${major}.${minor} (${subsystemVersionMeaning(`${major}.${minor}`, subsystem)})`;

export const renderHeaderVersions = (header: PeWindowsOptionalHeader): string =>
  renderDefinitionRow(
    "OperatingSystemVersion",
    formatOperatingSystemVersion(header.OSVersionMajor, header.OSVersionMinor, header.Subsystem),
    "Declared required OS version. Names identify version families, not proven compatibility."
  ) + renderDefinitionRow(
    "ImageVersion", `${header.ImageVersionMajor}.${header.ImageVersionMinor}`,
    "Author-defined image version; separate from file/product version resources."
  ) + renderDefinitionRow(
    "SubsystemVersion",
    formatSubsystemVersion(
      header.SubsystemVersionMajor, header.SubsystemVersionMinor, header.Subsystem
    ),
    "Minimum version of the selected subsystem; not necessarily a Windows release number."
  );
