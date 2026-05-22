"use strict";

import { escapeHtml } from "../../html-utils.js";

export type PeImportLibraryInfo = {
  summary: string;
};

const COMMON_WINDOWS_IMPORT_LIBRARY_INFO: Record<string, PeImportLibraryInfo> = {
  // Sources:
  // - RegOpenKeyExW requirements: Advapi32.dll
  //   https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw
  // - OpenSCManagerW requirements: Advapi32.dll
  //   https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw
  "advapi32.dll": {
    summary: "Registry, service-control-manager, and security/account management APIs."
  },
  // Source: BCryptOpenAlgorithmProvider requirements: Bcrypt.dll
  // https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider
  "bcrypt.dll": {
    summary: "Cryptography Next Generation primitive provider APIs."
  },
  // Source: InitCommonControlsEx loads/registers common controls from Comctl32.dll.
  // https://learn.microsoft.com/en-us/windows/win32/api/commctrl/nf-commctrl-initcommoncontrolsex
  "comctl32.dll": {
    summary: "Common Controls library for standard Windows UI control classes."
  },
  // Sources:
  // - CoCreateInstance requirements: Ole32.dll
  //   https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance
  // - CoInitializeEx requirements: Ole32.dll
  //   https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex
  "ole32.dll": {
    summary: "COM and OLE APIs such as COM initialization and object activation."
  },
  // Source: SysAllocString requirements: OleAut32.dll
  // https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-sysallocstring
  "oleaut32.dll": {
    summary: "OLE Automation APIs, including BSTR and VARIANT support."
  },
  // Source: CryptProtectData requirements: Crypt32.dll
  // https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
  "crypt32.dll": {
    summary: "CryptoAPI and DPAPI certificate/data-protection APIs."
  },
  // Source: SymInitialize requirements: Dbghelp.dll
  // https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-syminitialize
  "dbghelp.dll": {
    summary: "Debug Help APIs for symbols, stack walking, and dump-related tooling."
  },
  // Source: DwmIsCompositionEnabled requirements: Dwmapi.dll
  // https://learn.microsoft.com/en-us/windows/win32/api/dwmapi/nf-dwmapi-dwmiscompositionenabled
  "dwmapi.dll": {
    summary: "Desktop Window Manager composition and window-attribute APIs."
  },
  // Source: TextOutW requirements: Gdi32.dll
  // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-textoutw
  "gdi32.dll": {
    summary: "Graphics Device Interface drawing, text, font, and device-context APIs."
  },
  // Source: GdiplusStartup initializes Windows GDI+.
  // https://learn.microsoft.com/en-us/windows/win32/api/gdiplusinit/nf-gdiplusinit-gdiplusstartup
  "gdiplus.dll": {
    summary: "GDI+ startup and graphics APIs."
  },
  // Source: ImmGetContext requirements: Imm32.dll
  // https://learn.microsoft.com/en-us/windows/win32/api/immdev/nf-immdev-immgetcontext
  "imm32.dll": {
    summary: "Input Method Manager APIs for IME text input."
  },
  // Sources:
  // - CreateFileW requirements: Kernel32.dll
  //   https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
  // - OpenProcess requirements: Kernel32.dll
  //   https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
  "kernel32.dll": {
    summary: "Core Win32 file, process, thread, memory, synchronization, and loader APIs."
  },
  // Source: Universal CRT deployment names ucrtbase.dll as the UCRT DLL.
  // https://learn.microsoft.com/en-us/cpp/windows/universal-crt-deployment
  "ucrtbase.dll": {
    summary: "Universal C Runtime implementation."
  },
  // Source: Visual C++ deployment docs name msvcp140.dll as a C++ runtime library.
  // https://learn.microsoft.com/en-us/cpp/windows/deployment-in-visual-cpp
  "msvcp140.dll": {
    summary: "Microsoft Visual C++ standard library runtime."
  },
  // Source: Visual C++ deployment docs describe versioned Visual C++ runtime libraries.
  // https://learn.microsoft.com/en-us/cpp/windows/deployment-in-visual-cpp
  "vcruntime140.dll": {
    summary: "Microsoft Visual C++ runtime support library."
  },
  // Source: Use the C Run-Time describes the DLL CRT form as MSVCRT.
  // https://learn.microsoft.com/en-us/troubleshoot/developer/visualstudio/cpp/libraries/use-c-run-time
  "msvcrt.dll": {
    summary: "Microsoft C runtime DLL."
  },
  // Source: NCryptOpenStorageProvider requirements: Ncrypt.dll
  // https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptopenstorageprovider
  "ncrypt.dll": {
    summary: "CNG key storage provider APIs."
  },
  // Source: ShellExecuteW requirements: Shell32.dll
  // https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutew
  "shell32.dll": {
    summary: "Windows Shell APIs for launching and operating on shell items."
  },
  // Source: Shell and Shlwapi DLL Versions describes Shell32.dll and Shlwapi.dll.
  // https://learn.microsoft.com/en-us/windows/win32/shell/versions
  "shlwapi.dll": {
    summary: "Shell lightweight utility APIs used by shell and path/URL helpers."
  },
  // Source: AcquireCredentialsHandle requirements: Secur32.dll
  // https://learn.microsoft.com/en-us/windows/win32/secauthn/acquirecredentialshandle--ntlm
  "secur32.dll": {
    summary: "Security Support Provider Interface authentication APIs."
  },
  // Source: URLDownloadToFile requirements: Urlmon.dll
  // https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123%28v%3Dvs.85%29?redirectedfrom=MSDN
  "urlmon.dll": {
    summary: "URL Moniker and URL download/binding APIs."
  },
  // Source: MessageBoxW requirements: User32.dll
  // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw
  "user32.dll": {
    summary: "Window manager, message, input, menu, dialog, and user-interface APIs."
  },
  // Source: GetFileVersionInfoW requirements list Version.lib and the version API contract.
  // https://learn.microsoft.com/en-us/windows/win32/api/winver/nf-winver-getfileversioninfow
  "version.dll": {
    summary: "Version-resource query APIs such as GetFileVersionInfo."
  },
  // Sources:
  // - About WinHTTP describes Windows HTTP Services.
  //   https://learn.microsoft.com/en-us/windows/win32/winhttp/about-winhttp
  // - WinHttpOpen initializes WinHTTP usage.
  //   https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpopen
  "winhttp.dll": {
    summary: "Windows HTTP Services client APIs, suited to services and server scenarios."
  },
  // Source: InternetOpenW initializes WinINet and requires Wininet.dll.
  // https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenw
  "wininet.dll": {
    summary: "WinINet internet client APIs for interactive desktop applications."
  },
  // Source: WSAStartup initiates use of the Winsock DLL; requirements: Ws2_32.dll.
  // https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsastartup
  "ws2_32.dll": {
    summary: "Winsock 2 networking APIs."
  },
  // Source: WTSEnumerateSessionsW is part of the wtsapi32.h API surface.
  // https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/
  "wtsapi32.dll": {
    summary: "Remote Desktop Services session and terminal-server APIs."
  }
};

const normalizeImportLibraryName = (name: string): string => {
  const trimmedName = name.trim().replace(/\\/g, "/");
  const lastSlashIndex = trimmedName.lastIndexOf("/");
  if (lastSlashIndex < 0) return trimmedName.toLowerCase();
  return trimmedName.slice(lastSlashIndex + 1).toLowerCase();
};

// Microsoft "Windows API sets" documents contract names as api-/ext-* names ending in l<n>-<n>-<n>.
const isApiSetContractName = (name: string): boolean =>
  /^(api|ext)-.+-l\d+-\d+-\d+(?:\.dll)?$/i.test(name);

export const getImportLibraryInfo = (name: string): PeImportLibraryInfo | null => {
  const normalizedName = normalizeImportLibraryName(name);
  if (!normalizedName) return null;
  if (isApiSetContractName(normalizedName)) {
    return {
      summary:
        "Windows API set contract: a loader-level virtual DLL name mapped to an implementation."
    };
  }
  return COMMON_WINDOWS_IMPORT_LIBRARY_INFO[normalizedName] ?? null;
};

export const renderImportLibraryNameWithInfo = (name: string): string => {
  const displayName = name || "(unknown DLL)";
  const info = getImportLibraryInfo(displayName);
  if (!info) return escapeHtml(displayName);
  return `${escapeHtml(displayName)}<div class="smallNote" style="margin:0">${
    escapeHtml(info.summary)
  }</div>`;
};

export const renderImportLibraryInfoNote = (name: string): string => {
  const info = getImportLibraryInfo(name);
  return info ? escapeHtml(info.summary) : "";
};
