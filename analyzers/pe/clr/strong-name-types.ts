"use strict";

export interface PeClrStrongName {
  status: "absent" | "present" | "delay-signed" | "truncated" | "unmapped";
  publicKeyToken: string | null;
  verification: "valid" | "invalid" | "unknown";
  verificationNote: string;
  issues: string[];
}
