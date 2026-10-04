"use strict";

import { sha1 } from "@noble/hashes/legacy.js";
import type { ClrAssemblyIdentity } from "./metadata-assembly-identity.js";

// Display-name lexer and attribute grammar, including unknown-attribute compatibility:
// https://github.com/dotnet/runtime/blob/main/src/libraries/Common/src/System/Reflection/AssemblyNameParser.cs
type NameToken = { kind: "text"; value: string } | { kind: "," | "=" | "end" };
const escapes: Readonly<Record<string, string>> = {
  "\\": "\\", ",": ",", "=": "=", "'": "'", "\"": "\"", "t": "\t", "r": "\r", "n": "\n"
};

class AssemblyNameCursor {
  private offset = 0;
  constructor(private readonly text: string) {}

  next(): NameToken | null {
    while (this.offset < this.text.length && /[ \r\n\t]/.test(this.text[this.offset]!)) this.offset++;
    const character = this.text[this.offset];
    if (character == null) return { kind: "end" };
    if (character === "," || character === "=") { this.offset++; return { kind: character }; }
    if (character === "\"" || character === "'") { this.offset++; return this.readQuoted(character); }
    return this.readUnquoted();
  }

  private readQuoted(quote: string): NameToken | null {
    let value = "";
    while (this.offset < this.text.length) {
      if (this.text[this.offset] === quote) { this.offset++; return { kind: "text", value }; }
      const character = this.readCharacter();
      if (character == null) return null;
      value += character;
    }
    return null;
  }

  private readUnquoted(): NameToken | null {
    let value = "";
    while (this.offset < this.text.length) {
      if (this.text[this.offset] === "," || this.text[this.offset] === "=") break;
      if (this.text[this.offset] === "\"" || this.text[this.offset] === "'") return null;
      const character = this.readCharacter();
      if (character == null) return null;
      value += character;
    }
    return { kind: "text", value: value.replace(/[ \r\n\t]+$/, "") };
  }

  private readCharacter(): string | null {
    const character = this.text[this.offset++];
    if (character == null || character === "\0") return null;
    return character === "\\" ? escapes[this.text[this.offset++] ?? ""] ?? null : character;
  }
}

const assemblyVersion = (value: string): string | null => {
  if (!/^\d+\.\d+(?:\.\d+){0,2}$/.test(value)) return null;
  const components = value.split(".").map(Number);
  // The runtime display grammar uses UInt16 components; 65535 marks unspecified build/revision.
  if (components.some(component => component > 65535) ||
    components[0] === 65535 || components[1] === 65535) return null;
  return components.slice(0, components[2] === 65535 ? 2 : components[3] === 65535 ? 3 : components.length).join(".");
};

const publicKeyToken = (value: string): string | null => {
  if (!value || value.toLowerCase() === "null") return "";
  if (!/^(?:[\da-f]{2})+$/i.test(value)) return null;
  // Strong-name token is the reversed last eight bytes of SHA-1 of a full key.
  return Array.from(sha1(Uint8Array.from(value.match(/../g)!, byte => Number.parseInt(byte, 16))).slice(-8).reverse(),
    byte => byte.toString(16).padStart(2, "0")).join("");
};

const processorArchitecture = (value: string): number | null => {
  // Runtime ProcessorArchitecture enum: MSIL=1, X86=2, IA64=3, Amd64=4, Arm=5.
  const index = ["msil", "x86", "ia64", "amd64", "arm"].indexOf(value.toLowerCase());
  return index < 0 ? null : index + 1;
};

const tokenValue = (value: string): string | null => !value || value.toLowerCase() === "null" ? "" :
  /^[\da-f]{16}$/i.test(value) ? value.toLowerCase() : null;

const attributeValue = (key: keyof typeof properties, value: string): string | number | null => {
  switch (key) {
    case "version": return assemblyVersion(value);
    case "culture": return value.toLowerCase() === "neutral" ? "" : value.toLowerCase();
    case "publickey": return publicKeyToken(value);
    case "publickeytoken": return tokenValue(value);
    case "contenttype": return value.toLowerCase() === "windowsruntime" ? 0x200 : null;
    case "processorarchitecture": return processorArchitecture(value);
  }
};

const properties = {
  version: "version", culture: "culture", publickey: "publicKeyToken", publickeytoken: "publicKeyToken",
  contenttype: "contentType", processorarchitecture: "processorArchitecture"
} as const;

const readAttribute = (
  identity: Partial<ClrAssemblyIdentity>, seen: Set<string>, key: string, value: string
): boolean => {
  const property = Object.hasOwn(properties, key) ? properties[key as keyof typeof properties] : undefined;
  if (!property && key !== "retargetable") return true;
  const uniqueKey = property ?? key;
  if (seen.has(uniqueKey)) return false;
  seen.add(uniqueKey);
  if (key === "retargetable") return /^(yes|no)$/i.test(value);
  const decoded = attributeValue(key as keyof typeof properties, value);
  if (decoded == null) return false;
  Object.assign(identity, { [property!]: decoded });
  return true;
};

export const parseClrAssemblyName = (name: string): Partial<ClrAssemblyIdentity> | null => {
  const cursor = new AssemblyNameCursor(name);
  const first = cursor.next();
  if (first?.kind !== "text" || !first.value) return null;
  const identity: Partial<ClrAssemblyIdentity> = { name: first.value.toLowerCase() };
  const seen = new Set<string>();
  let token = cursor.next();
  while (token) {
    if (token.kind === "end") return identity;
    if (token.kind !== "," || !readDisplayAttribute(cursor, identity, seen)) return null;
    token = cursor.next();
  }
  return null;
};

const readDisplayAttribute = (
  cursor: AssemblyNameCursor, identity: Partial<ClrAssemblyIdentity>, seen: Set<string>
): boolean => {
  const key = cursor.next();
  if (key?.kind !== "text" || !key.value || cursor.next()?.kind !== "=") return false;
  const value = cursor.next();
  return value?.kind === "text" && readAttribute(identity, seen, key.value.toLowerCase(), value.value);
};
