// One bounded streaming pass; large data/custom payloads need not be retained in memory.
export class WasmStream {
  position = 0;
  private chunk: Uint8Array = new Uint8Array();
  private cursor = 0;
  constructor(private readonly source: ReadableStreamDefaultReader<Uint8Array>,
    readonly size: number) {}
  private checkSize(size: number): void {
    if (!Number.isSafeInteger(size) || size < 0 || size > this.size - this.position) {
      throw new Error("Invalid or truncated file range");
    }
  }
  async consume(size: number, destination?: Uint8Array): Promise<void> {
    this.checkSize(size);
    await this.copy(size, destination);
  }
  private async copy(size: number, destination?: Uint8Array): Promise<void> {
    let copied = 0;
    while (copied < size) {
      if (this.cursor === this.chunk.length) {
        const next = await this.source.read();
        if (next.done) throw new Error("Truncated file stream");
        this.chunk = next.value;
        this.cursor = 0;
      }
      const count = Math.min(size - copied, this.chunk.length - this.cursor);
      destination?.set(this.chunk.subarray(this.cursor, this.cursor + count), copied);
      this.cursor += count;
      this.position += count;
      copied += count;
    }
  }
  async read(size: number): Promise<Uint8Array> {
    this.checkSize(size);
    const bytes = new Uint8Array(size);
    await this.copy(size, bytes);
    return bytes;
  }
  async byte(): Promise<number> {
    if (this.position >= this.size) throw new Error("Truncated file");
    while (this.cursor === this.chunk.length) {
      const next = await this.source.read();
      if (next.done) throw new Error("Truncated file stream");
      this.chunk = next.value;
      this.cursor = 0;
    }
    this.position++;
    return this.chunk[this.cursor++]!;
  }
}
