"use strict";

export const SIGNATURE_V4 = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];
export const SIGNATURE_V5 = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00];

export const LHD_SPLIT_BEFORE = 0x0001;
export const LHD_SPLIT_AFTER = 0x0002;
export const LHD_PASSWORD = 0x0004;
export const LHD_SOLID = 0x0010;
export const LHD_DIRECTORY = 0x00e0;
export const LHD_WINDOWMASK = 0x00e0;
export const LHD_LARGE = 0x0100;
export const LHD_UNICODE = 0x0200;
export const LHD_SALT = 0x0400;
export const LHD_EXTTIME = 0x1000;
export const LONG_BLOCK = 0x8000;

export const MHD_VOLUME = 0x0001;
export const MHD_COMMENT = 0x0002;
export const MHD_LOCK = 0x0004;
export const MHD_SOLID = 0x0008;
export const MHD_PROTECT = 0x0040;
export const MHD_PASSWORD_FLAG = 0x0080;
export const MHD_FIRSTVOLUME = 0x0100;

export const HEAD3_MAIN = 0x73;
export const HEAD3_FILE = 0x74;
export const HEAD3_ENDARC = 0x7b;

export const HFL_EXTRA = 0x0001;
export const HFL_DATA = 0x0002;
export const HFL_SPLITBEFORE = 0x0008;
export const HFL_SPLITAFTER = 0x0010;
export const HFL_CHILD = 0x0020;
export const HFL_INHERITED = 0x0040;

export const MHFL_VOLUME = 0x0001;
export const MHFL_VOLNUMBER = 0x0002;
export const MHFL_SOLID = 0x0004;
export const MHFL_PROTECT = 0x0008;
export const MHFL_LOCK = 0x0010;

export const FHFL_DIRECTORY = 0x0001;
export const FHFL_UTIME = 0x0002;
export const FHFL_CRC32 = 0x0004;
export const FHFL_UNPUNKNOWN = 0x0008;

export const EHFL_NEXTVOLUME = 0x0001;

export const FCI_SOLID = 0x00000040;

export const RAR4_METHODS = ["Store", "Fastest", "Fast", "Normal", "Good", "Best"];
export const RAR5_METHODS = ["Store", "Faster", "Fast", "Normal", "Good", "Best"];
