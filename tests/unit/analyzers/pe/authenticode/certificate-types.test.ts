import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeWinCertificate } from "../../../../../analyzers/pe/authenticode/index.js";
import {
  createCmsDigestAlgorithmFixture,
  wrapCmsDigestWinCertificate
} from "../../../../fixtures/cms-digest-algorithms.js";

// Values are independent of the production table: Microsoft WIN_CERTIFICATE / WinTrust.h,
// and UEFI 2.10 section 32.2.4. Unconfirmed legacy labels remain numeric.
// https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-win_certificate
// https://uefi.org/specs/UEFI/2.10/32_Secure_Boot_and_Driver_Signing.html#win-certificate
for (const [certificateType, typeName] of [
  [0x0001, "X.509 (individual)"],
  [0x0004, "TS stack signing"],
  [0x0009, "PKCS1_SIGN"],
  [0x0ef0, "EFI PKCS#1 v1.5"],
  [0x0ef1, "EFI GUID"],
  [0x000a, "Type 0x000a"],
  [0x0ef2, "Type 0x0ef2"]
] as const) {
  void test(`decodeWinCertificate preserves type ${certificateType} without decoding it as CMS`, () => {
    const bytes = wrapCmsDigestWinCertificate(
      createCmsDigestAlgorithmFixture([], []), certificateType
    );

    const decoded = decodeWinCertificate(bytes, bytes.length, 0);

    assert.equal(decoded.certificateType, certificateType);
    assert.equal(decoded.typeName, typeName);
    assert.equal(decoded.authenticode, undefined);
    assert.equal(decoded.warnings, undefined);
  });
}
