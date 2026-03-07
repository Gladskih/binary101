"use strict";

export type ThinMachOFixtureLayout = {
  buildVersionCommandOffset: number;
  codeSignatureCommandOffset: number;
  codeSignatureOffset: number;
  dyldCommandOffset: number;
  dylibCommandOffset: number;
  headerFlagsOffset: number;
  headerNcmdsOffset: number;
  headerSizeofcmdsOffset: number;
  headerSize: number;
  linkeditSegmentCommandOffset: number;
  mainCommandOffset: number;
  sourceVersionCommandOffset: number;
  stroff: number;
  symoff: number;
  symtabCommandOffset: number;
  textOffset: number;
  textSectionFlagsOffset: number;
  textSectionOffsetFieldOffset: number;
  textSegmentCommandOffset: number;
  uuidCommandOffset: number;
};

export type ThinMachOFixture = {
  bytes: Uint8Array;
  layout: ThinMachOFixtureLayout;
};
