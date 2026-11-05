# PE header version names and evidence

Reviewed on 2026-11-06. The renderer preserves the two integer components of each
version and adds known names. This is a correspondence catalogue, **not an exhaustive
list of Windows SKUs, an enumeration of valid PE values, or a compatibility detector**.
The original catalogue was incomplete; the review below expands it without treating
compiler defaults or unsupported aliases as operating-system releases.

## Meaning and limits

Microsoft's [PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
defines separate OS, image, and subsystem version pairs. Each component occupies two
bytes. An image version is author-defined and has no universal product-name mapping.
The OS version and subsystem version can differ; they must not be copied from each
other or combined into a claim about which Windows installation built the file.

Names identify version families. They do not identify an edition, architecture,
service pack, build, set of imported APIs, or all systems capable of loading the file.
For example, Microsoft's archived [KB Q125705](https://www.betaarchive.com/wiki/index.php/Microsoft_KB_Archive/125705)
documents that subsystem 4.0 can also load on NT 3.5 and Win32s 1.15 or later.
Thus a 4.0 label must not be interpreted as an exact minimum compatible Windows release.
For Q125705 the indexed archive excerpt was available; the mirror denied access to
the full page during this review.

Unknown pairs are displayed unchanged. In particular, 3.1 is not substituted for
3.10, 3.5 for 3.50, or 6.30 for 6.3. Some prose uses padded or inconsistent version
notation; the actual integer fields and linker parsing take precedence.

## Accepted Windows family correspondences

| Pair | Names in the renderer | Evidence |
| --- | --- | --- |
| 3.10 | Windows NT 3.1; Windows 3.1 with Win32s for GUI images | [Chappell](https://www.geoffchappell.com/studies/windows/km/versions.htm), [Wine VersionData](https://github.com/wine-mirror/wine/blob/c42c1532a8b8a767d5e23b527ea874368c202ed0/dlls/ntdll/version.c), [NT 3.1 / Win32s linking experiment](https://www.os2museum.com/wp/retro-porting-to-nt-3-1/) |
| 3.50 | Windows NT 3.5 | Chappell's inspected kernel versions and distribution names |
| 3.51 | Windows NT 3.51 | Chappell; Wine's NT351 entry |
| 4.0 | Windows NT 4.0; Windows 95 | [Microsoft historical version pairs](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rap/187b8ded-16d0-4c17-9a75-c7b47795df93); Wine |
| 4.10 | Windows 98; Windows 98 Second Edition | Microsoft's historical pairs; Wine explicitly records both builds with 4/10 |
| 4.90 | Windows Me | Microsoft's historical pairs; Wine |
| 5.0 | Windows 2000 | [Microsoft OS version table](https://learn.microsoft.com/en-us/windows/win32/sysinfo/operating-system-version) |
| 5.1 | Windows XP; original Windows XP 64-Bit Edition for Itanium | Microsoft OS table; [MS04-016's separate 5.1 IA64 payloads](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2004/ms04-016) |
| 5.2 | XP Professional x64; XP 64-Bit Edition Version 2003 for Itanium; Server 2003; Server 2003 R2; Home Server | [OSVERSIONINFOEX](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoexa); MS04-016's 5.2 IA64 payloads |
| 6.0 | Vista; Server 2008 | Microsoft OS version table |
| 6.1 | Windows 7; Server 2008 R2; Home Server 2011 | Microsoft OS version table; [Microsoft's server product bases](https://learn.microsoft.com/en-us/windows/win32/srvnodes/windows-server) |
| 6.2 | Windows 8; Server 2012; Windows RT | Microsoft OS version table; [RT owner's system-information output](https://learn.microsoft.com/en-us/answers/questions/2327976/install-windows-10-from-usb-stick-on-windows-rt) |
| 6.3 | Windows 8.1; Server 2012 R2; Windows RT 8.1 | Microsoft OS version table; [RT 8.1 owner's command output](https://learn.microsoft.com/en-us/answers/questions/2850345/windows-rt-8-1-wont-activate-after-multiple-resets) |
| 10.0 | Windows 10; Windows 11; Server 2016, 2019, 2022, 2025 | Microsoft OS version table; [MS-RPRN product behavior](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/e81cbc09-ab05-4a32-ae4a-8ec57b436c43) |

RT evidence includes first-hand system output, rather than an additional Microsoft
version-table entry. The Itanium XP and Home Server correspondences additionally use
documented shared system components/base releases; these are family correspondences,
not observations of every corresponding application's PE optional header.

## Subsystem context

- Windows GUI/CUI use the Windows family catalogue. The Win32s name is GUI-specific:
  Microsoft's [KB Q130808](https://jeffpar.github.io/kbarchive/kb/130/Q130808/)
  documents the missing Console API. This is an interface-support distinction, not
  a claim that the Win32s loader rejects every CUI image. A first-hand
  [Win32s compatibility list](https://stephan.win31.de/w32slist.htm) reports console-mode
  tools that run without console output. Keep this nuance when interpreting the label.
- CE uses its own namespace. The exact 4/20 subsystem pair is documented by
  [CeGCC](https://cegcc.sourceforge.net/docs/details.html); the manufacturer's
  [LXE MX3X manual, page 323](https://www.manualslib.com/manual/290367/Lxe-Mx3x.html?page=323)
  identifies its 4.20 system as Windows CE .NET 4.2. Other CE pairs retain the generic
  Windows CE context until their exact numeric/product correspondence is substantiated.
  An OS field such as 4.0 is not promoted to a CE product version from that alone.
- Native, Native Windows/Win9x, OS/2, POSIX, Xbox and Windows Boot Application retain
  their own context. Their version fields do not automatically select a desktop OS.
  [Microsoft /SUBSYSTEM](https://learn.microsoft.com/en-us/cpp/build/reference/subsystem-specify-subsystem)
  documents environment-specific defaults, including Native/WDM 1.10 and POSIX 19.90.
- EFI versions are not interpreted as UEFI specification revisions. EDK II's
  [GenFw](https://github.com/tianocore/edk2/blob/master/BaseTools/Source/C/GenFw/GenFw.c)
  normally clears the optional-header OS and subsystem version fields.

## Compiler and reverse-engineering cross-checks

These are checks of the specific files below, not claims that every module in each
project has been exhaustively searched.

| Source snapshot | Relevant observation |
| --- | --- |
| [LLVM LLD DriverUtils](https://github.com/llvm/llvm-project/blob/4ccb556e20235a1d84bc5643524a1ca1a579922e/lld/COFF/DriverUtils.cpp), [subsystem tests](https://github.com/llvm/llvm-project/blob/4ccb556e20235a1d84bc5643524a1ca1a579922e/lld/test/COFF/subsystem.test), [Writer](https://github.com/llvm/llvm-project/blob/4ccb556e20235a1d84bc5643524a1ca1a579922e/lld/COFF/Writer.cpp) | Parses components as decimal integers. Tests use arbitrary 8.9/8.09 and independently set /osversion. Writer stores OS, image and subsystem pairs separately. |
| [GNU binutils pe.em](https://github.com/RTEMS/sourceware-mirror-binutils-gdb/blob/2364e17098e63e0af17c5329dec1ca8cd82c6cbb/ld/emultempl/pe.em) | OS defaults and subsystem defaults are separate, configurable linker values. ARM/WinCE can use a different subsystem default from desktop targets. |
| [Open Watcom loadpe.c](https://github.com/open-watcom/open-watcom-v2/blob/558748e2bd28d330e37c0a2f2d8a2a4766118625/bld/wl/c/loadpe.c), [exepe.h](https://github.com/open-watcom/open-watcom-v2/blob/558748e2bd28d330e37c0a2f2d8a2a4766118625/bld/watcom/h/exepe.h) | Can emit OS 1.11 and subsystem 3.10. Also defines RDOS subsystem 0xAD05 with default OS 8.8 and subsystem 1.0. These producer conventions do not establish Windows 1.11 or a released RDOS version 8.8. |
| [Wine version.c](https://github.com/wine-mirror/wine/blob/c42c1532a8b8a767d5e23b527ea874368c202ed0/dlls/ntdll/version.c) | VersionData supplies independent Win32s, Win9x and NT examples. Comments that report possible Win95 OSR 4.3 values are insufficient by themselves to add a released-OS alias. |
| [Ghidra OptionalHeader](https://github.com/NationalSecurityAgency/ghidra/blob/84782699d6d112e598e3f5077bf0d5ddeea63f0c/Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/pe/OptionalHeader.java) | Preserves distinct raw WORD components and provides getters; the inspected class supplies no exhaustive product-name catalogue. |
| [LIEF OptionalHeader](https://github.com/lief-project/LIEF/blob/e2c497eb83695fefe88fe01f3da692a048f1a824/src/PE/OptionalHeader.cpp) | Preserves separate raw version fields and has producer defaults, rather than making those fields an exhaustive OS enum. |
| [radare2 PE parser](https://github.com/radareorg/radare2/blob/06a7c9d35468676cc3fe6ea299885cf53aa8ad9b/libr/bin/format/pe/pe.c) | Reads the separate integer pairs; a raw parser field is not evidence of a new product-name correspondence. |
| [RetDec PeDetector](https://github.com/avast/retdec/blob/9450585772e6f1c18e5f0b2ad5518a18d6bce71e/src/fileinfo/file_detector/pe_detector.cpp) | The inspected detector lists deeper processing of these fields as future work, not as an authoritative OS catalogue. |
| [Corkami PE notes](https://github.com/corkami/docs/blob/fd339bf6bebe7aa086a02a95b5a4fd9ef0c1bd28/PE/PE.md) | Hand-built loader experiments show why loader behavior and arbitrary header metadata must be kept separate. The ss63 example stores 6/3 even where prose uses 6.30. |

## Completeness boundary

This review covers the released classic NT/Win9x family version numbers and selected
documented aliases. It does **not** establish an exhaustive list of Embedded, IoT,
Thin PC, POSReady, Small Business, Storage, HPC, MultiPoint, Hyper-V, servicing-channel,
CE/Mobile/Pocket PC, prerelease, or third-party OS product names.

Those omissions are deliberate limits, not evidence that these products have unique
version pairs or cannot use PE. Add an alias only with evidence for its exact numeric
pair and namespace. Custom subsystem IDs such as RDOS need their own supported
subsystem definition before they can receive a product-specific version explanation.
Neither a compiler default nor another tool's heuristic is sufficient on its own.
