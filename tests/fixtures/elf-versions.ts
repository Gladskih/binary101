import { relocationFixture, relocationSection } from "./elf-relocations.js";

// LSB 10.7: Verdef(20), Verdaux(8), Verneed(16), Vernaux(16), Versym(2).
// https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/symversion.html
export const elfVersionFixture = (order: "little" | "big" = "little") => {
  const fixture = relocationFixture(64, order);
  const little = order === "little";
  const strings = new TextEncoder().encode("\0LIB_1\0libsample.so\0LIB_2\0");
  fixture.bytes.set(strings, 384);
  fixture.elf.sections = [
    relocationSection(0, { type: 0 }),
    relocationSection(1, { type: 3, offset: 384n, size: BigInt(strings.length) }),
    relocationSection(2, { type: 11, offset: 256n, size: 48n, entsize: 24n, link: 1 }),
    relocationSection(3, { type: 0x6ffffffd, offset: 64n, size: 28n, link: 1, info: 1 }),
    relocationSection(4, { type: 0x6ffffffe, offset: 128n, size: 32n, link: 1, info: 1 }),
    relocationSection(5, { type: 0x6fffffff, offset: 192n, size: 4n, entsize: 2n, link: 2 })
  ];
  fixture.view.setUint16(64, 1, little);
  fixture.view.setUint16(68, 2, little);
  fixture.view.setUint16(70, 1, little);
  fixture.view.setUint32(72, 0x1234, little); // Incidental hash, preserved verbatim.
  fixture.view.setUint32(76, 20, little);
  fixture.view.setUint32(84, 1, little);
  fixture.view.setUint16(128, 1, little);
  fixture.view.setUint16(130, 1, little);
  fixture.view.setUint32(132, 7, little);
  fixture.view.setUint32(136, 16, little);
  fixture.view.setUint16(150, 3, little);
  fixture.view.setUint32(152, 20, little);
  fixture.view.setUint16(194, 0x8002, little); // Hidden version index 2.
  return fixture;
};
