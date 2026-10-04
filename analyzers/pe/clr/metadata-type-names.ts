"use strict";

// Reflection reserves these characters in identifiers. '+' between names denotes nesting.
// https://learn.microsoft.com/en-us/dotnet/fundamentals/reflection/specifying-fully-qualified-type-names
export const escapeClrTypeNamePart = (name: string): string => name.replace(/[\\,+[\]*&]/g, "\\$&");

export const clrTypeFullName = (namespaceName: string | null, name: string | null): string | null =>
  name ? (namespaceName ? `${escapeClrTypeNamePart(namespaceName)}.` : "") + escapeClrTypeNamePart(name) : null;
