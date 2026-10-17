export const createWindowsTrustSnapshot = () => ({
  // Version 1 is emitted by scripts/dump-windows-authenticode-trust.ps1.
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  source: "Test certificate stores",
  trustedCAs: [{ thumbprint: "ABCD", derBase64: Buffer.from("certificate fixture").toString("base64") }],
  revokedCAs: []
});
