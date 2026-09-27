import assert from "node:assert/strict";
import { test } from "node:test";
import * as asn1js from "asn1js";
import {
  decodePkcs7, decodeWinCertificate
} from "../../../../../analyzers/pe/authenticode/index.js";
import { collectDigestAlgorithmConsistencyWarnings } from "../../../../../analyzers/pe/authenticode/digest-algorithm-consistency.js";
import {
  createCmsDigestAlgorithmFixture,
  createCmsDigestSignedDataSchema,
  createCmsDigestSignerSchema,
  encodeCmsDigestSignedData,
  wrapCmsDigestWinCertificate
} from "../../../../fixtures/cms-digest-algorithms.js";

// NIST CSOR hash algorithm OIDs: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
const SHA256_OID = "2.16.840.1.101.3.4.2.1";
const SHA512_OID = "2.16.840.1.101.3.4.2.3";

void test("decodeWinCertificate keeps consistency warnings alongside trailing-data warnings", () => {
  const bytes = wrapCmsDigestWinCertificate(Uint8Array.from([
    ...createCmsDigestAlgorithmFixture([SHA256_OID, SHA512_OID], [SHA256_OID]),
    1 // Nonzero trailing data must not be stripped as WIN_CERTIFICATE padding.
  ]));

  const decoded = decodeWinCertificate(bytes, bytes.length, 0);

  assert.deepEqual(decoded.authenticode?.warnings, [
    "Certificate blob has trailing bytes after the DER ContentInfo payload.",
    "SignedData digestAlgorithms lists sha512, but no SignerInfo uses it (RFC 5652 section 5.1)."
  ]);
});

void test("decodePkcs7 checks signer algorithms against an empty declared set", () => {
  const decoded = decodePkcs7(createCmsDigestAlgorithmFixture([], [SHA256_OID]));

  assert.deepEqual(decoded.warnings, [
    "No digest algorithms listed.",
    "SignerInfo uses sha256, which is absent from SignedData digestAlgorithms (RFC 5652 section 5.3 recommends inclusion)."
  ]);
});

void test("decodePkcs7 keeps consistency warnings when a signer name cannot be read", () => {
  const signedData = createCmsDigestSignedDataSchema([SHA256_OID, SHA512_OID], []);
  const signer = createCmsDigestSignerSchema(SHA256_OID);
  // RFC 5652 section 5.3: version 1 uses issuerAndSerialNumber as the signer identifier.
  signer.valueBlock.value[0] = new asn1js.Integer({ value: 1 });
  signer.valueBlock.value[1] = new asn1js.Sequence({ value: [
    new asn1js.Sequence(), new asn1js.Integer({ value: 1 })
  ] });
  signedData.valueBlock.value[3] = new asn1js.Set({ value: [signer] });

  const decoded = decodePkcs7(encodeCmsDigestSignedData(signedData));

  assert.deepEqual(decoded.warnings, [
    "Certificate name has no readable attributes.",
    "SignedData digestAlgorithms lists sha512, but no SignerInfo uses it (RFC 5652 section 5.1)."
  ]);
});

void test("decodePkcs7 warns about a declared digest algorithm unused by signers", () => {
  const decoded = decodePkcs7(createCmsDigestAlgorithmFixture(
    [SHA256_OID, SHA512_OID], [SHA256_OID]
  ));

  assert.ok(decoded.warnings?.includes(
    "SignedData digestAlgorithms lists sha512, but no SignerInfo uses it (RFC 5652 section 5.1)."
  ));
  assert.deepEqual(decoded.digestAlgorithms, ["sha256", "sha512"]);
  assert.strictEqual(decoded.signers?.[0]?.digestAlgorithmName, "sha256");
});

void test("decodePkcs7 warns about a signer digest algorithm absent from the declared set", () => {
  const decoded = decodePkcs7(createCmsDigestAlgorithmFixture([SHA512_OID], [SHA256_OID]));

  assert.ok(decoded.warnings?.includes(
    "SignerInfo uses sha256, which is absent from SignedData digestAlgorithms (RFC 5652 section 5.3 recommends inclusion)."
  ));
});

void test("decodePkcs7 accepts matching digest sets regardless of order or signer multiplicity", () => {
  const decoded = decodePkcs7(createCmsDigestAlgorithmFixture(
    [SHA512_OID, SHA256_OID], [SHA256_OID, SHA512_OID, SHA256_OID]
  ));

  assert.strictEqual(decoded.warnings, undefined);
  assert.strictEqual(decoded.signerCount, 3);
});

void test("decodePkcs7 warns once for a missing algorithm shared by several signers", () => {
  const decoded = decodePkcs7(createCmsDigestAlgorithmFixture(
    [SHA512_OID], [SHA256_OID, SHA256_OID]
  ));

  assert.strictEqual(decoded.warnings?.filter(warning => warning.includes("SignerInfo uses sha256")).length, 1);
});

void test("decodePkcs7 warns about listed digest algorithms when signerInfos is empty", () => {
  const decoded = decodePkcs7(createCmsDigestAlgorithmFixture([SHA256_OID], []));

  assert.ok(decoded.warnings?.some(warning => warning.includes("no SignerInfo uses it")));
});

void test("decodePkcs7 accepts an empty digest set and no signers without consistency warnings", () => {
  const decoded = decodePkcs7(createCmsDigestAlgorithmFixture([], []));

  assert.deepEqual(decoded.warnings, ["No digest algorithms listed."]);
});

void test("collectDigestAlgorithmConsistencyWarnings skips absent or incompletely parsed fields", () => {
  assert.deepEqual(collectDigestAlgorithmConsistencyWarnings({}), []);
  assert.deepEqual(collectDigestAlgorithmConsistencyWarnings({ digestAlgorithms: ["sha256"] }), []);
  assert.deepEqual(collectDigestAlgorithmConsistencyWarnings({
    digestAlgorithms: ["sha256"], signerCount: 1
  }), []);
  assert.deepEqual(collectDigestAlgorithmConsistencyWarnings({
    digestAlgorithms: ["sha256"], signerCount: 1, signers: [{}]
  }), []);
});

void test("collectDigestAlgorithmConsistencyWarnings compares unknown algorithms by OID", () => {
  // An unregistered OID stands in for an algorithm unknown to this analyzer.
  const decoded = decodePkcs7(createCmsDigestAlgorithmFixture(["1.2.3.4"], ["1.2.3.4"]));

  assert.strictEqual(decoded.warnings, undefined);
  assert.deepEqual(decoded.digestAlgorithms, ["1.2.3.4"]);
  assert.strictEqual(decoded.signers?.[0]?.digestAlgorithm, "1.2.3.4");
});

void test("decodePkcs7 skips consistency checks when a signer digest is missing", () => {
  const signedData = createCmsDigestSignedDataSchema([SHA256_OID], []);
  const signer = createCmsDigestSignerSchema(SHA256_OID);
  // RFC 5652 section 5.3: digestAlgorithm is the third SignerInfo field.
  signer.valueBlock.value[2] = new asn1js.Sequence();
  signedData.valueBlock.value[3] = new asn1js.Set({ value: [signer] });

  const decoded = decodePkcs7(encodeCmsDigestSignedData(signedData));

  assert.strictEqual(decoded.warnings?.some(warning => warning.includes("no SignerInfo uses it")), false);
  assert.strictEqual(decoded.warnings?.some(warning => warning.includes("SignerInfo uses")), false);
});

void test("decodePkcs7 reports a digest AlgorithmIdentifier without an OID", () => {
  const signedData = createCmsDigestSignedDataSchema([], [SHA256_OID]);
  // RFC 5652 section 5.1: digestAlgorithms is the second SignedData field.
  signedData.valueBlock.value[1] = new asn1js.Set({ value: [new asn1js.Sequence()] });

  const decoded = decodePkcs7(encodeCmsDigestSignedData(signedData));

  assert.ok(decoded.warnings?.some(warning => warning.includes("missing or out-of-bounds OID")));
  assert.strictEqual(decoded.warnings?.some(warning => warning.includes("SignerInfo uses")), false);
});

void test("decodePkcs7 reports malformed OIDs in the declared digest set", () => {
  const signedData = createCmsDigestSignedDataSchema([], [SHA256_OID]);
  signedData.valueBlock.value[1] = new asn1js.Set({ value: [
    new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier()] })
  ] });

  const decoded = decodePkcs7(encodeCmsDigestSignedData(signedData));

  assert.ok(decoded.warnings?.includes("SignedData digestAlgorithms contains a malformed OID."));
});

void test("decodePkcs7 keeps parsed algorithms but skips consistency checks after a malformed entry", () => {
  const signedData = createCmsDigestSignedDataSchema([], [SHA256_OID]);
  signedData.valueBlock.value[1] = new asn1js.Set({ value: [
    new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: SHA512_OID })] }),
    new asn1js.Null()
  ] });

  const decoded = decodePkcs7(encodeCmsDigestSignedData(signedData));

  assert.deepEqual(decoded.digestAlgorithms, ["sha512"]);
  assert.strictEqual(decoded.warnings?.some(warning => warning.includes("no SignerInfo uses it")), false);
  assert.strictEqual(decoded.warnings?.some(warning => warning.includes("SignerInfo uses")), false);
});

void test("decodePkcs7 skips consistency checks after a truncated signer entry", () => {
  const signedData = createCmsDigestSignedDataSchema([SHA256_OID, SHA512_OID], []);
  signedData.valueBlock.value[3] = new asn1js.Set({ value: [
    createCmsDigestSignerSchema(SHA256_OID), new asn1js.Sequence()
  ] });
  const bytes = encodeCmsDigestSignedData(signedData);
  // X.690: the final empty SEQUENCE now declares one content octet beyond EOF.
  bytes[bytes.length - 1] = 1;

  const decoded = decodePkcs7(bytes);

  assert.ok(decoded.warnings?.includes("SignerInfos SET contains malformed or truncated entries."));
  assert.strictEqual(decoded.warnings?.some(warning => warning.includes("no SignerInfo uses it")), false);
});

void test("decodePkcs7 reports an unparseable SignerInfo instead of treating its digest as unused", () => {
  const signedData = createCmsDigestSignedDataSchema([SHA256_OID], []);
  signedData.valueBlock.value[3] = new asn1js.Set({ value: [new asn1js.Sequence()] });

  const decoded = decodePkcs7(encodeCmsDigestSignedData(signedData));

  assert.ok(decoded.warnings?.includes("SignerInfos SET contains an unparseable SignerInfo entry."));
  assert.strictEqual(decoded.warnings?.some(warning => warning.includes("no SignerInfo uses it")), false);
});

void test("decodePkcs7 skips unused-algorithm warnings for malformed signer entries", () => {
  const signedData = createCmsDigestSignedDataSchema([SHA256_OID, SHA512_OID], [SHA256_OID]);
  // RFC 5652 section 5.1: signerInfos is the final SignedData field.
  signedData.valueBlock.value[3] = new asn1js.Set({ value: [
    createCmsDigestSignerSchema(SHA256_OID), new asn1js.Null()
  ] });

  const decoded = decodePkcs7(encodeCmsDigestSignedData(signedData));

  assert.ok(decoded.warnings?.includes("SignerInfos SET contains a malformed SignerInfo entry."));
  assert.strictEqual(decoded.warnings?.some(warning => warning.includes("no SignerInfo uses it")), false);
});

void test("decodePkcs7 skips consistency checks for malformed digest algorithm entries", () => {
  const signedData = createCmsDigestSignedDataSchema([], [SHA256_OID]);
  // RFC 5652 section 5.1: digestAlgorithms is the second SignedData field.
  signedData.valueBlock.value[1] = new asn1js.Set({ value: [new asn1js.Null()] });

  const decoded = decodePkcs7(encodeCmsDigestSignedData(signedData));

  assert.ok(decoded.warnings?.some(warning => warning.includes("malformed or truncated AlgorithmIdentifier")));
  assert.strictEqual(decoded.warnings?.some(warning => warning.includes("SignerInfo uses")), false);
});
