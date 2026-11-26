#include <arm_acle.h>
#include <arm_neon.h>

__declspec(dllexport) uint32_t checksum_byte(uint32_t checksum, uint8_t value) {
    return __crc32b(checksum, value);
}

__declspec(dllexport) uint8x16_t aes_round(uint8x16_t block, uint8x16_t round_key) {
    return vaeseq_u8(block, round_key);
}
