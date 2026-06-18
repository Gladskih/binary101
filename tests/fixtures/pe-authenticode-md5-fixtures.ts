"use strict";

import * as asn1js from "asn1js";
import { createPrivateKey, sign as nodeSign } from "node:crypto";
import type { Certificate } from "../../analyzers/pe/authenticode/pkijs-runtime.js";
import {
  addTimestampUnsignedAttributes,
  createCertificateChain,
  createSignedData,
  encodeContentInfo
} from "./pe-authenticode-signed-cms-fixtures.js";
import { toArrayBuffer } from "./pe-authenticode-cms-helpers.js";

const MD5_WITH_RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.4";

export const signCertificateWithMd5Rsa = async (
  certificate: Certificate,
  privateKey: CryptoKey
): Promise<void> => {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);
  certificate.signatureAlgorithm.algorithmId = MD5_WITH_RSA_ENCRYPTION_OID;
  certificate.signatureAlgorithm.algorithmParams = new asn1js.Null();
  certificate.signatureValue = new asn1js.BitString({
    valueHex: toArrayBuffer(
      nodeSign("RSA-MD5", certificate.tbsView, createPrivateKey({
        key: Buffer.from(pkcs8),
        format: "der",
        type: "pkcs8"
      }))
    )
  });
};

export const createMd5RootSignatureCmsFixture = async (): Promise<Uint8Array> => {
  const chain = await createCertificateChain();
  await signCertificateWithMd5Rsa(chain.root, chain.rootPrivateKey);
  const signedData = await createSignedData("00", chain);
  const signerInfo = signedData.signerInfos[0];
  if (!signerInfo) throw new Error("Signed CMS fixture is missing the primary signer.");
  await addTimestampUnsignedAttributes(signerInfo, chain);
  return encodeContentInfo(signedData);
};
