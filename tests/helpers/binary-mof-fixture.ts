// bmfdec.c and bmfparse.c document the FOMB container and DS-01 literal codes.
// https://github.com/pali/bmfdec
const word = (value: number): number[] => [value & 0xff, value >> 8 & 0xff];
const dword = (value: number): number[] => [value & 0xff, value >> 8 & 0xff,
  value >> 16 & 0xff, value >> 24 & 0xff];
const unicode = (value: string): number[] => [...value].flatMap(char =>
  word(char.charCodeAt(0))).concat([0, 0]);

export const packDsCodes = (codes: Array<{ value: number; bits: number }>): Uint8Array => {
  const bits: number[] = [];
  for (const code of codes) {
    for (let index = 0; index < code.bits; index += 1) {
      bits.push(code.value >> index & 1);
    }
  }
  const output = new Uint8Array(Math.ceil(bits.length / 8));
  bits.forEach((bit, index) => { output[index >> 3] = (output[index >> 3] ?? 0) |
    (bit << (index & 7)); });
  return output;
};

export const encodeDsLiterals = (data: Uint8Array): Uint8Array => packDsCodes([
  { value: 0x5344, bits: 16 }, { value: 0x0100, bits: 16 },
  ...Array.from(data, byte => ({ value: ((byte & 127) << 2) | (byte & 128 ? 1 : 2),
    bits: 9 })),
  { value: 7, bits: 3 }, { value: 4095, bits: 12 }
]);

export const decodedMofFixture = (identityProperty = "__CLASS"): Uint8Array => {
  const qualifierName = unicode("guid");
  const qualifierValue = unicode("{12345678-1234-1234-1234-123456789abc}");
  const qualifier = [...dword(16 + qualifierName.length + qualifierValue.length),
    ...dword(8), ...dword(0), ...dword(qualifierName.length),
    ...qualifierName, ...qualifierValue];
  const qualifierBlock = [...dword(8 + qualifier.length), ...dword(1), ...qualifier];
  const className = unicode("TestClass");
  const propertyName = unicode(identityProperty);
  const classProperty = [
    ...dword(20 + propertyName.length + className.length), ...dword(8), ...dword(0),
    ...dword(propertyName.length), ...dword(0xffffffff), ...propertyName, ...className
  ];
  const variableName = unicode("Payload");
  const variable = [...dword(20 + variableName.length + 8), ...dword(0x13),
    ...dword(0), ...dword(0xffffffff), ...dword(variableName.length),
    ...variableName, ...dword(8), ...dword(0)];
  const variableBlock = [...dword(8 + classProperty.length + variable.length),
    ...dword(2), ...classProperty, ...variable];
  const classData = [...qualifierBlock, ...variableBlock];
  const methodName = unicode("Refresh");
  const method = [...dword(20 + methodName.length + 8), ...dword(0), ...dword(0),
    ...dword(methodName.length), ...dword(methodName.length), ...methodName,
    ...dword(8), ...dword(0)];
  const methodBlock = [...dword(8 + method.length), ...dword(1), ...method];
  const classRecord = [...dword(20 + classData.length + methodBlock.length),
    ...dword(0), ...dword(qualifierBlock.length), ...dword(classData.length), ...dword(0),
    ...classData, ...methodBlock];
  const firstPartEnd = 20 + classRecord.length;
  return Uint8Array.from([70, 79, 77, 66, ...dword(firstPartEnd),
    ...dword(1), ...dword(1), ...dword(1), ...classRecord,
    ...new TextEncoder().encode("BMOFQUALFLAVOR11"), ...dword(0)]);
};

export const compressedMofFixture = (): Uint8Array => {
  const decoded = decodedMofFixture();
  const compressed = encodeDsLiterals(decoded);
  return Uint8Array.from([70, 79, 77, 66, ...dword(1), ...dword(compressed.length),
    ...dword(decoded.length), ...compressed]);
};
