import * as asn1js from "asn1js";
import {
  Attribute,
  ContentInfo,
  SignedAndUnsignedAttributes,
  type SignedData
} from "../../analyzers/pe/authenticode/pkijs-runtime.js";
import { createCertificateChain, createSignedData } from "./pe-authenticode-signed-cms-fixtures.js";

const encodePrimitiveContentInfo = (signedData: SignedData): Uint8Array => {
  const content = signedData.toSchema(true);
  const encap = content instanceof asn1js.Sequence ? content.valueBlock.value[2] : undefined;
  const wrapper = encap instanceof asn1js.Sequence ? encap.valueBlock.value[1] : undefined;
  const octets = wrapper instanceof asn1js.Constructed ? wrapper.valueBlock.value[0] : undefined;
  if (!(wrapper instanceof asn1js.Constructed) || !(octets instanceof asn1js.OctetString)) {
    throw new Error("CMS fixture lacks encapsulated octets.");
  }
  wrapper.valueBlock.value[0] = new asn1js.OctetString({ valueHex: octets.getValue() });
  return new Uint8Array(
    new ContentInfo({ contentType: ContentInfo.SIGNED_DATA, content }).toSchema().toBER()
  );
};
const attachNestedValues = (parent: SignedData, values: unknown[]): Uint8Array => {
  const signer = parent.signerInfos[0];
  if (!signer) throw new Error("Nested CMS fixture is missing the primary signer.");
  signer.unsignedAttrs = new SignedAndUnsignedAttributes({
    type: 1,
    attributes: [new Attribute({
      // Microsoft SPC_NESTED_SIGNATURE_OBJID, as emitted by osslsigncode.
      type: "1.3.6.1.4.1.311.2.4.1",
      values
    })]
  });
  return encodePrimitiveContentInfo(parent);
};

export const createNestedAuthenticodeCmsPayload = async (
  parentDigest: string, nestedDigest: string
): Promise<Uint8Array> => {
  const chain = await createCertificateChain();
  const parent = await createSignedData(parentDigest, chain);
  const nested = await createSignedData(nestedDigest, chain);
  return attachNestedValues(parent,
    [new asn1js.Null(), asn1js.fromBER(encodePrimitiveContentInfo(nested)).result]);
};

export const createNestedAuthenticodeLimitPayload = async (digest: string): Promise<Uint8Array> => {
  const chain = await createCertificateChain();
  const leaf = encodePrimitiveContentInfo(await createSignedData(digest, chain));
  let deep = leaf;
  // The analysis permits 4 nested levels and 16 checks below the root.
  for (let index = 0; index < 5; index += 1) {
    deep = attachNestedValues(await createSignedData(digest, chain), [asn1js.fromBER(deep).result]);
  }
  return attachNestedValues(await createSignedData(digest, chain), [
    asn1js.fromBER(deep).result,
    ...Array.from({ length: 16 }, () => asn1js.fromBER(leaf).result)
  ]);
};
