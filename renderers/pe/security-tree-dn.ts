"use strict";

const DN_ATTRIBUTE_LABELS: Record<string, string> = {
  C: "Country",
  ST: "State or Province",
  L: "Locality",
  O: "Organization",
  OU: "Organizational Unit",
  CN: "Common Name",
  DC: "Domain Component",
  STREET: "Street Address",
  EMAILADDRESS: "Email Address",
  E: "Email Address",
  SERIALNUMBER: "Serial Number",
  SN: "Surname",
  GN: "Given Name"
};

const splitDistinguishedName = (value: string): string[] => {
  const parts: string[] = [];
  let current = "";
  let escaped = false;
  let quoted = false;
  for (const character of value) {
    if (escaped) {
      current += character;
      escaped = false;
      continue;
    }
    if (character === "\\") {
      current += character;
      escaped = true;
      continue;
    }
    if (character === "\"") {
      current += character;
      quoted = !quoted;
      continue;
    }
    if (character === "," && !quoted) {
      parts.push(current.trim());
      current = "";
      continue;
    }
    current += character;
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
};

export const formatDistinguishedNameTooltip = (value: string | undefined): string | undefined => {
  if (!value) return undefined;
  const lines = splitDistinguishedName(value).map(part => {
    const separatorIndex = part.indexOf("=");
    if (separatorIndex <= 0) return part;
    const key = part.slice(0, separatorIndex).trim();
    const attributeName = DN_ATTRIBUTE_LABELS[key.toUpperCase()] || key;
    const attributeValue = part.slice(separatorIndex + 1).trim();
    return `${attributeName} (${key}): ${attributeValue}`;
  });
  return lines.length ? lines.join("\n") : value;
};

export const formatCertificateTitle = (
  certificateIndex: number,
  subject: string | undefined
): string =>
  `Certificate &#8470;${certificateIndex + 1}: ${subject || "Subject absent"}`;

export const formatSignerTitle = (signerIndex: number, subject: string | undefined): string =>
  `Signer ${signerIndex + 1}: ${subject || "Subject absent"}`;
