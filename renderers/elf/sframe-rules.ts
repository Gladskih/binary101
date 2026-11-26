import type { ElfSFrameHeader, ElfSFrameRow } from "../../analyzers/elf/sframe-types.js";

// GNU Binutils SFrame specification §§2.2.1, 2.4.1, 3.1 and 3.2.
// https://sourceware.org/binutils/docs-2.46/sframe-spec.html
export const SFRAME_ABI = { AARCH64_BE: 1, AARCH64_LE: 2, AMD64: 3, S390X: 4 } as const;
const unavailable = "—";
const signedOffset = (base: string, offset: number): string =>
  offset < 0 ? `${base} − ${-offset}` : `${base} + ${offset}`;
const cfaStackSlot = (offset: number | undefined): string =>
  offset == null ? unavailable : `[${signedOffset("CFA", offset)}]`;
const unsigned = (word: number, info: number): number =>
  word < 0 ? word + 2 ** (8 * 2 ** ((info >> 5) & 3)) : word;

const registerRule = (offset: number | undefined, info: number): string =>
  offset != null && (offset & 1) ? `r${unsigned(offset, info) >>> 1}` : cfaStackSlot(offset);

// s390x stores (actual CFA offset - 160) / 8 in the CFA data word.
const cfaOffset = (abi: number, word: number): number => abi === SFRAME_ABI.S390X ? word * 8 + 160 : word;

const s390xRules = (row: ElfSFrameRow, version: number, base: string, cfa: number): string[] => {
  const location = version === 2 ? registerRule : cfaStackSlot;
  return [signedOffset(base, cfaOffset(SFRAME_ABI.S390X, cfa)), location(row.words[2], row.info),
    location(row.words[1] || undefined, row.info)];
};

const defaultRules = (row: ElfSFrameRow, header: ElfSFrameHeader, version: number): string[] => {
  const [cfa, second, third] = row.words;
  if (cfa == null) return [unavailable, unavailable, version >= 2 ? "Undefined" : unavailable];
  const base = row.info & 1 ? "SP" : "FP";
  if (header.abi === SFRAME_ABI.S390X) return s390xRules(row, version, base, cfa);
  const fp = header.fixedFpOffset || (header.fixedRaOffset ? second : third);
  const ra = header.fixedRaOffset || second;
  return [signedOffset(base, cfa), cfaStackSlot(fp), cfaStackSlot(ra)];
};

const flexibleLocation = (control: number, offset: number | undefined): string => {
  if (offset == null || (control & 4) || !(control & 1) && control >>> 3) return unavailable;
  const base = control & 1 ? `r${control >>> 3}` : "CFA";
  const expression = signedOffset(base, offset);
  return control & 2 ? `[${expression}]` : expression;
};

const flexibleRules = (row: ElfSFrameRow, header: ElfSFrameHeader): string[] => {
  const [cfaControl, cfa, raControl] = row.words;
  if (cfaControl == null) return [unavailable, unavailable, "Undefined"];
  // A missing RA rule occupies one padding word when FP data follows.
  const fpIndex = raControl ? 4 : 3;
  const fpControl = row.words[fpIndex];
  return [
    cfaControl & 1
      ? flexibleLocation(unsigned(cfaControl, row.info), cfa == null ? cfa : cfaOffset(header.abi, cfa))
      : unavailable,
    fpControl ? flexibleLocation(unsigned(fpControl, row.info), row.words[fpIndex + 1])
      : cfaStackSlot(header.fixedFpOffset || undefined),
    raControl ? flexibleLocation(unsigned(raControl, row.info), row.words[3])
      : cfaStackSlot(header.fixedRaOffset || undefined)
  ];
};

export const sframeRules = (row: ElfSFrameRow, header: ElfSFrameHeader, version: number,
  kind: number): string[] => {
  if (!Object.values(SFRAME_ABI).some(value => value === header.abi)) {
    return [unavailable, unavailable, unavailable];
  }
  if (kind === 0) return defaultRules(row, header, version);
  if (kind === 1) return flexibleRules(row, header);
  return [unavailable, unavailable, unavailable];
};
