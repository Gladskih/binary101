// NibbleWriter::WriteEncodedU32/I32: low nibble first, big-endian groups of three bits.
// https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/nibblestream.h
export class NibbleReader {
  #position = 0;
  constructor(readonly bytes: Uint8Array) {}

  get byteOffset(): number { return Math.ceil(this.#position / 2); }

  unsigned(): number {
    let value = 0;
    let nibble: number;
    do {
      if (this.#position >= this.bytes.length * 2) throw new Error("Nibble stream is truncated.");
      nibble = (this.bytes[Math.floor(this.#position / 2)]! >>> ((this.#position++ & 1) * 4)) & 15;
      value = value * 8 + (nibble & 7);
      if (value > 0xffffffff) throw new Error("Nibble integer exceeds UInt32.");
    } while (nibble & 8);
    return value;
  }

  signed(): number {
    const value = this.unsigned();
    return (value & 1) ? -Math.floor(value / 2) : value / 2;
  }
}
