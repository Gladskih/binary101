"use strict";

import type { PeSubtype } from "./subtype.js";

const PE_SUBTYPE_LABELS: Record<PeSubtype, string> = {
  "winmd": "Windows Metadata (WinMD)",
  "dotnet-reference-assembly": ".NET reference assembly (metadata-only)",
  "clr-native-image": "CLR native image",
  "linux-boot-kernel": "Linux boot kernel (bzImage)",
  "intel-txt-mle-nested-pe": "Intel TXT measured launch environment (MLE)",
  "dos-stub-nested-pe": "Nested PE in DOS stub",
  "mui-resource-image": "MUI resource-only image"
};

export const peSubtypeLabel = (subtype: PeSubtype): string =>
  PE_SUBTYPE_LABELS[subtype] ?? subtype;
