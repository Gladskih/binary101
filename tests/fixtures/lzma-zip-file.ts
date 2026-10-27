// Independently produced with Python 3.14 zipfile.ZipFile(compression=ZIP_LZMA):
// writestr("payload.bin", b"DATA"), writestr("empty.bin", b"").
export const lzmaZipFile = (): Uint8Array<ArrayBuffer> => Uint8Array.from(Buffer.from(
  "UEsDBD8AAgAOAHSpW13XHmabFwAAAAQAAAALAAAAcGF5bG9hZC5iaW4JBAUAXQAAgAAAIhBGzWmlPH//+m/gA" +
  "FBLAwQ/AAIADgB0qVtdAAAAABMAAAAAAAAACQAAAGVtcHR5LmJpbgkEBQBdAACAAACD//v//8AAAABQSwECPwM/" +
  "AAIADgB0qVtd1x5mmxcAAAAEAAAACwAAAAAAAAAAAAAAgAEAAAAAcGF5bG9hZC5iaW5QSwECPwM/AAIADgB0qVtd" +
  "AAAAABMAAAAAAAAACQAAAAAAAAAAAAAAgAFAAAAAZW1wdHkuYmluUEsFBgAAAAACAAIAcAAAAHoAAAAAAA==", "base64"));
