"use strict";

// DateTime.FromBinary uses two high kind bits; local values store UTC ticks and may wrap.
// Recovering local wall-clock time requires the original machine's time zone.
// https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/DateTime.cs
export const formatResourceDateTime = (binary: bigint, version: number): string | null => {
  if (version === 2 && (binary & 0x8000000000000000n) !== 0n) {
    return `Local DateTime (binary 0x${BigInt.asUintN(64, binary).toString(16).padStart(16, "0")}; ` +
      `original time zone unavailable)`;
  }
  const ticks = version === 1 ? binary : binary & 0x3fffffffffffffffn;
  // DateTime.MaxValue.Ticks, and the tick count of the Unix epoch (0001 -> 1970).
  if (ticks < 0n || ticks > 3155378975999999999n) return null;
  const date = new Date(Number(ticks / 10000n) - 62135596800000);
  const text = date.toISOString().slice(0, 19) + `.${(ticks % 10000000n).toString().padStart(7, "0")}`;
  return text + (version === 2 && (binary & 0x4000000000000000n) !== 0n ? "Z" : " (Unspecified)");
};

// TimeSpan's constant format is [-][d.]hh:mm:ss[.fffffff].
// https://learn.microsoft.com/en-us/dotnet/standard/base-types/standard-timespan-format-strings
export const formatResourceTimeSpan = (ticks: bigint): string => {
  const magnitude = ticks < 0n ? -ticks : ticks;
  const seconds = magnitude / 10000000n;
  const days = seconds / 86400n;
  const hours = ((seconds / 3600n) % 24n).toString().padStart(2, "0");
  const minutes = ((seconds / 60n) % 60n).toString().padStart(2, "0");
  const fraction = magnitude % 10000000n;
  return `${ticks < 0n ? "-" : ""}${days ? `${days}.` : ""}${hours}:${minutes}:` +
    `${(seconds % 60n).toString().padStart(2, "0")}` +
    (fraction ? `.${fraction.toString().padStart(7, "0")}` : "");
};
