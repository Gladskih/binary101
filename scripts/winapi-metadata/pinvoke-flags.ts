"use strict";

// ECMA-335 II.23.1.8 defines PInvokeAttributes: charset, call-convention,
// NoMangle, and SupportsLastError are encoded in ImplMap.MappingFlags.
const CHAR_SET_MASK = 0x0006;
const CHAR_SET_ANSI = 0x0002;
const CHAR_SET_UNICODE = 0x0004;
const CHAR_SET_AUTO = 0x0006;
const SUPPORTS_LAST_ERROR = 0x0040;
const CALL_CONVENTION_MASK = 0x0700;
const CALL_CONVENTION_WINAPI = 0x0100;
const CALL_CONVENTION_CDECL = 0x0200;
const CALL_CONVENTION_STDCALL = 0x0300;
const CALL_CONVENTION_THISCALL = 0x0400;
const CALL_CONVENTION_FASTCALL = 0x0500;

export const decodeCharacterSet = (mappingFlags: number): string | null => {
  const charset = mappingFlags & CHAR_SET_MASK;
  if (charset === CHAR_SET_ANSI) return "ansi";
  if (charset === CHAR_SET_UNICODE) return "unicode";
  if (charset === CHAR_SET_AUTO) return "auto";
  return null;
};

export const decodeCallingConvention = (mappingFlags: number): string => {
  const convention = mappingFlags & CALL_CONVENTION_MASK;
  if (convention === CALL_CONVENTION_WINAPI) return "winapi";
  if (convention === CALL_CONVENTION_CDECL) return "cdecl";
  if (convention === CALL_CONVENTION_STDCALL) return "stdcall";
  if (convention === CALL_CONVENTION_THISCALL) return "thiscall";
  if (convention === CALL_CONVENTION_FASTCALL) return "fastcall";
  return "platform-default";
};

export const mappingSupportsLastError = (mappingFlags: number): boolean =>
  (mappingFlags & SUPPORTS_LAST_ERROR) !== 0;

export const isVariadicConvention = (mappingFlags: number): boolean =>
  (mappingFlags & CALL_CONVENTION_MASK) === CALL_CONVENTION_CDECL;
