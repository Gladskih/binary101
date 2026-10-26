// 7-Zip 26.05 (official Linux x64, SHA-256 22cf82fc...a3b232e):
// 7zz a plain.7z payload.bin -m0=lzma2:d12 -mhc=off -mtm=off -mtc=off -mta=off -ms=off
// payload.bin is bytes(range(256)) * 32. The second archive wraps the actual 7z
// header with Python liblzma FORMAT_RAW/FILTER_LZMA2, dictionary=4096; 7zz t passes.
// Container framing follows DOC/7zFormat.txt; no container code is in the WASM package.
export const lzma2SevenZipPlain = (): Uint8Array => Uint8Array.from(Buffer.from(
  "N3q8ryccAAQ1cyPEFwEAAAAAAABSAAAAAAAAAF+rusjgH/8BD10AAABSUAqE+ZuygCGpadYn4D4GWl8E" +
  "jVPUBLo5VwUJwVUk3p24cVkxYKGf+W9Jc/LI6oy6GospaSGA/jODZq9GbeyeiYoLg/A8DomOP+1f" +
  "556Q2Rz/MvSy4DlRstIUFbTFcbrbBuN5mp+7OMGwAKyTC6oGGQMSCBVbm8hI8DIu/i2gh8jwpODS" +
  "UeuNZ1aSsk2ExfGGMd9qYlvCeS3Z9zxzunR0B9g8qVYiJKFm+FqEXzBn0vZLSS5/IOvb+BAOlHh" +
  "3xz9r77TNleJv9kRuBs8LghrL23rwV42Y/5DAPubBEkF17gMolusT+6cozK8yu6QOJfJYsN7YVhx" +
  "m8OIbOXb5l/+Po8gv9K3y2zfcTNblAAABBAYAAQmBFwAHCwEAASEhAQAMoAAACAoBB1NntgAABQEZ" +
  "CgAAAAAAAAAAAAARGQBwAGEAeQBsAG8AYQBkAC4AYgBpAG4AAAAVBgEAIID/gQAA", "base64"));

export const lzma2SevenZipEncoded = (): Uint8Array => Uint8Array.from(Buffer.from(
  "N3q8ryccAATZ6O3uaAEAAAAAAAAbAAAAAAAAAC+z8bDgH/8BD10AAABSUAqE+ZuygCGpadYn4D4GWl8E" +
  "jVPUBLo5VwUJwVUk3p24cVkxYKGf+W9Jc/LI6oy6GospaSGA/jODZq9GbeyeiYoLg/A8DomOP+1f" +
  "556Q2Rz/MvSy4DlRstIUFbTFcbrbBuN5mp+7OMGwAKyTC6oGGQMSCBVbm8hI8DIu/i2gh8jwpODS" +
  "UeuNZ1aSsk2ExfGGMd9qYlvCeS3Z9zxzunR0B9g8qVYiJKFm+FqEXzBn0vZLSS5/IOvb+BAOlHh" +
  "3xz9r77TNleJv9kRuBs8LghrL23rwV42Y/5DAPubBEkF17gMolusT+6cozK8yu6QOJfJYsN7YVhx" +
  "m8OIbOXb5l/+Po8gv9K3y2zfcTNblAADgAFEASV0AAIEzB64P1ThUSvnGZtqN8/MDo9Mg3Df0Frdu" +
  "YY1nRptsQo9RNmoCRfe+R5TBMote41KcZTmEVvTXI1j07ekMdAtpW682gAAAAAAXBoEXAQlRAAcLAQAB" +
  "ISEBAAxSCgFfq7rIAAA=", "base64"));

export const lzma2SevenZipPayload = (): Uint8Array =>
  Uint8Array.from({ length: 8192 }, (_, index) => index % 256);
