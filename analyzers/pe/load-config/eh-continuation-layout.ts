// IMAGE_LOAD_CONFIG_DIRECTORY32/64 field offsets in the Windows SDK winnt.h.
// https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h
export const EH_CONTINUATION_LAYOUT = {
  4: { table: 0xa4, count: 0xa8 }, 8: { table: 0x108, count: 0x110 }
} as const;
