// Fixed marker bytes from dotnet/runtime. They equal SHA-256 of UTF-8
// ".net core bundle\n" (including LF); upstream's short comment omits that LF.
// https://github.com/dotnet/runtime/blob/main/src/native/corehost/apphost/bundle_marker.c
export const BUNDLE_SIGNATURE = Uint8Array.from([
  0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
  0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
  0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
  0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae
]);
// EMBED_HASH_FULL_UTF8 is the hex SHA-256 of "foobar", not a filename.
// https://github.com/dotnet/runtime/blob/main/src/native/corehost/apphost/apphost.c
export const APP_BINARY_PLACEHOLDER_TEXT =
  "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2";
export const APP_BINARY_PLACEHOLDER = new TextEncoder().encode(APP_BINARY_PLACEHOLDER_TEXT);
// Enumerate the ASCII case-insensitive filename suffix explicitly. The final NUL
// follows the embedded UTF-8 path contract in apphost.c above.
export const BINDING_PATTERNS = [APP_BINARY_PLACEHOLDER,
  ...[".dll\0", ".dlL\0", ".dLl\0", ".dLL\0", ".Dll\0", ".DlL\0", ".DLl\0", ".DLL\0"]
    .map(suffix => new TextEncoder().encode(suffix))
];
