"use strict";

import { hex } from "../../binary-utils.js";

// Community-sourced Rich build labels:
// https://github.com/dishather/richprint/blob/master/comp_id.txt
interface RichBuildRange {
  first: number;
  last: number;
  label: string;
}

const RICH_BUILD_LABELS: Record<number, string> = {
  0x0000: "Imported Functions",
  0x0684: "VS97 v5.0 SP3 cvtres 5.00.1668",
  0x06b8: "VS98 v6.0 cvtres build 1720",
  0x06c8: "VS98 v6.0 SP6 cvtres build 1736",
  0x0883: "Windows Server 2003 DDK",
  0x08f4: "VS2003 v7.1 .NET Beta build 2292",
  0x0bec: "VS2003 v7.1 Free Toolkit .NET build 3052",
  0x0c05: "VS2003 v7.1 .NET build 3077",
  0x0fc3: "VS2003 v7.1 | Windows Server 2003 SP1 DDK build 4035",
  0x178e: "VS2003 v7.1 SP1 .NET build 6030",
  0x1c83: "MASM 6.13.7299",
  0x1c87: "VS97 v5.0 SP3 link 5.10.7303",
  0x1fe8: "VS98 v6.0 RTM/SP1/SP2 build 8168",
  0x1fe9: "VB 6.0/SP1/SP2 build 8169",
  0x20fc: "MASM 6.14.8444",
  0x20ff: "VC++ 6.0 SP3 build 8447",
  0x212f: "VB 6.0 SP3 build 8495",
  0x225f: "VS 6.0 SP4 build 8799",
  0x2263: "MASM 6.15.8803",
  0x2264: "VS 6 [SP5,SP6] build 8804",
  0x22ad: "VB 6.0 SP4 build 8877",
  0x2304: "VB 6.0 SP5 build 8964",
  0x2306: "VS 6.0 SP5 build 8966",
  0x2346: "VS 7.0 2000 Beta 1 build 9030",
  0x2354: "VS 6.0 SP5 Processor Pack build 9044",
  0x23d8: "Windows XP SP1 DDK",
  0x2426: "VS2001 v7.0 Beta 2 build 9254",
  0x24fa: "VS2002 v7.0 .NET build 9466",
  0x2636: "VB 6.0 SP6 / VC++ build 9782",
  0x26e3: "VS2002 v7.0 SP1 build 9955",
  0x501a: "VS2010 v10.0 Beta 1 build 20506",
  0x5089: "VS2013 v12.0 Preview build 20617",
  0x50e2: "VS2008 v9.0 Beta 2 build 20706",
  0x515b: "VS2013 v12.0 RC build 20827",
  0x520b: "VS2010 v10.0 Beta 2 build 21003",
  0x520d: "VS2013 v12.[0,1] build 21005",
  0x521e: "VS2008 v9.0 build 21022",
  0x527a: "VS2013 v12.0 Nov CTP build 21114",
  0x56c7: "VS2015 v14.0 build 22215",
  0x59f2: "VS2015 v14.0 build 23026",
  0x5bd2: "VS2015 v14.0 UPD1 build 23506",
  0x5d10: "VS2015 v14.0 UPD2 build 23824",
  0x5d6e: "VS2015 v14.0 UPD2 build 23918",
  0x5e92: "VS2015 v14.0 UPD3 build 24210",
  0x5e95: "VS2015 UPD3 build 24213",
  0x5e97: "VS2015 v14.0 UPD3.1 build 24215",
  0x5e9a: "VS2015 v14.0 build 24218",
  0x61b9: "VS2017 v15.[0,1] build 25017",
  0x61bb: "VS2017 v14.1 build 25019",
  0x63a2: "VS2017 v15.2 build 25019",
  0x63a3: "VS2017 v15.3.3 build 25507",
  0x63c6: "VS2017 v15.4.4 build 25542",
  0x63cb: "VS2017 v15.4.5 build 25547",
  0x64e6: "VS2017 v15 build 25830",
  0x64e7: "VS2017 v15.5.2 build 25831",
  0x64ea: "VS2017 v15.5.[3,4] build 25834",
  0x64eb: "VS2017 v15.5.[5,6,7] build 25835",
  0x6610: "VS2017 v15.6.[0,1,2] build 26128",
  0x6611: "VS2017 v15.6.[3,4] build 26129",
  0x6613: "VS2017 v15.6.6 build 26131",
  0x6614: "VS2017 v15.6.7 build 26132",
  0x6723: "VS2017 v15.1 build 26403",
  0x673c: "VS2017 v15.7.[0,1] build 26428",
  0x673d: "VS2017 v15.7.2 build 26429",
  0x673e: "VS2017 v15.7.3 build 26430",
  0x673f: "VS2017 v15.7.4 build 26431",
  0x6741: "VS2017 v15.7.5 build 26433",
  0x685b: "VS2017 v15.8.? build 26715",
  0x6866: "VS2017 v15.8.0 build 26726",
  0x6869: "VS2017 v15.8.4 build 26729",
  0x686a: "VS2017 v15.8.9 build 26730",
  0x686c: "VS2017 v15.8.5 build 26732",
  0x698f: "VS2017 v15.9.[0,1] build 27023",
  0x6990: "VS2017 v15.9.2 build 27024",
  0x6991: "VS2017 v15.9.4 build 27025",
  0x6992: "VS2017 v15.9.5 build 27026",
  0x6993: "VS2017 v15.9.7 build 27027",
  0x6996: "VS2017 v15.9.11 build 27030",
  0x6997: "VS2017 v15.9.12 build 27031",
  0x6998: "VS2017 v15.9.14 build 27032",
  0x699a: "VS2017 v15.9.16 build 27034",
  0x6b74: "VS2019 v16.0.0 build 27508",
  0x6c36: "VS2019 v16.1.2 UPD1 build 27702",
  0x6d01: "VS2019 v16.2.3 UPD2 build 27905",
  0x6dc9: "VS2019 v16.3.2 UPD3 build 28105",
  0x766f: "VS2010 v10.0 build 30319",
  0x7674: "VS2013 v12.0 UPD2 RC build 30324",
  0x7725: "VS2013 v12.0 UPD2 build 30501",
  0x7803: "VS2013 v12.0 UPD3 build 30723",
  0x7809: "VS2008 v9.0 SP1 build 30729",
  0x797d: "VS2013 v12.0 UPD4 build 31101",
  0x9d1b: "VS2010 v10.0 SP1 build 40219",
  0x9d76: "Windows Server 2003 SP1 DDK (for AMD64)",
  0x9e9f: "VS2005 v8.0 Beta 1 build 40607",
  0x9eb5: "VS2013 v12.0 UPD5 build 40629",
  0xc427: "VS2005 v8.0 Beta 2 build 50215",
  0xc490: "VS2005 v8.0 build 50320",
  0xc497: "VS2005 v8.0 (Beta) build 50327",
  0xc627: "VS2005 v8.0 | VS2012 v11.0 build 50727",
  0xc751: "VS2012 v11.0 Nov CTP build 51025",
  0xc7a2: "VS2012 v11.0 UPD1 build 51106",
  0xeb9b: "VS2012 v11.0 UPD2 build 60315",
  0xecc2: "VS2012 v11.0 UPD3 build 60610",
  0xee66: "VS2012 v11.0 UPD4 build 61030"
};

// Build ranges are bounded by community comp_id.txt entries from richprint.
const RICH_BUILD_RANGES: RichBuildRange[] = [
  { first: 0x8aaf, last: 0x8d91, label: "VS2026-era MSVC" },
  { first: 0x7a61, last: 0x899a, label: "VS2022-era MSVC" },
  { first: 0x6b74, last: 0x75cf, label: "VS2019-era MSVC" },
  { first: 0x61b9, last: 0x699a, label: "VS2017-era MSVC" },
  { first: 0x56c7, last: 0x5e9a, label: "VS2015-era MSVC" }
];

export const resolveRichBuildLabel = (buildNumber: number): string => {
  const exactLabel = RICH_BUILD_LABELS[buildNumber];
  if (exactLabel) return exactLabel;
  const range = RICH_BUILD_RANGES.find(
    candidate => buildNumber >= candidate.first && buildNumber <= candidate.last
  );
  if (range) return `${range.label} build ${buildNumber} (exact release not in catalog)`;
  return `Unrecognized build ${hex(buildNumber, 4)} (${buildNumber})`;
};
