"use strict";

import type { PeSubtype } from "./subtype.js";

const PE_SUBTYPE_LABELS: Record<PeSubtype, string> = {
  "winmd": "Windows Metadata (WinMD)",
  "dotnet-reference-assembly": ".NET reference assembly (metadata-only)",
  "clr-native-image": "CLR native image",
  "mui-resource-image": "MUI resource-only image"
};

export const peSubtypeLabel = (subtype: PeSubtype): string =>
  PE_SUBTYPE_LABELS[subtype] ?? subtype;
