#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// Read-only SEC_IMAGE_NO_EXECUTE mapping: no DllMain, imports, entry point or
// analyzed instructions are executed. Windows itself interprets unwind metadata.
// https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingw
static DWORD64 original(unsigned index) { return 0x1111000000000000ull + index * 0x10101; }
static DWORD64 value(const std::string &token, DWORD64 entry) {
  if (token[0] == 'S') return entry + std::stoll(token.substr(1));
  if (token[0] == 'R') return original((unsigned)std::stoul(token.substr(1)));
  if (token[0] == 'C') return std::stoull(token.substr(1), nullptr, 16);
  return 0x3333000000000000ull;
}
static DWORD unwind(DWORD64 image, DWORD64 pc, RUNTIME_FUNCTION *runtime, CONTEXT *context) {
  __try {
    void *handler = nullptr;
    DWORD64 frame = 0;
    RtlVirtualUnwind(UNW_FLAG_NHANDLER, image, pc, runtime, context, &handler, &frame, nullptr);
    return 0;
  } __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
}
static std::wstring wide(const std::string &text) {
  std::wstring result(MultiByteToWideChar(CP_UTF8, 0, text.data(), (int)text.size(), nullptr, 0), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.data(), (int)text.size(), result.data(), (int)result.size());
  return result;
}
int main() {
  HANDLE file = INVALID_HANDLE_VALUE, mapping = nullptr;
  void *image = nullptr;
  std::string line;
  alignas(16) static unsigned char stack[1024 * 1024];
  while (std::getline(std::cin, line)) {
    if (line.empty()) continue;
    if (line[0] == 'F') {
      if (image) UnmapViewOfFile(image);
      if (mapping) CloseHandle(mapping);
      if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
      file = CreateFileW(wide(line.substr(2)).c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
      mapping = file == INVALID_HANDLE_VALUE ? nullptr :
        CreateFileMappingW(file, nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr);
      image = mapping ? MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0) : nullptr;
      continue;
    }
    std::istringstream input(line);
    char marker;
    unsigned id, begin, end, info, offset, mask, memoryCount;
    input >> marker >> id >> begin >> end >> info >> offset >> mask >> memoryCount;
    CONTEXT context = {};
    context.ContextFlags = CONTEXT_FULL;
    DWORD64 *registers[] = { &context.Rax, &context.Rcx, &context.Rdx, &context.Rbx,
      &context.Rsp, &context.Rbp, &context.Rsi, &context.Rdi, &context.R8, &context.R9,
      &context.R10, &context.R11, &context.R12, &context.R13, &context.R14, &context.R15 };
    M128A *vectors[] = { &context.Xmm0, &context.Xmm1, &context.Xmm2, &context.Xmm3,
      &context.Xmm4, &context.Xmm5, &context.Xmm6, &context.Xmm7, &context.Xmm8,
      &context.Xmm9, &context.Xmm10, &context.Xmm11, &context.Xmm12, &context.Xmm13,
      &context.Xmm14, &context.Xmm15 };
    std::memset(stack, 0, sizeof(stack));
    const DWORD64 entry = (DWORD64)(stack + sizeof(stack) / 2);
    const DWORD64 returnAddress = 0x2222333344445555ull;
    std::memcpy((void *)entry, &returnAddress, 8);
    std::string token;
    for (unsigned index = 0; index < 16; index++) {
      input >> token;
      *registers[index] = value(token, entry);
    }
    for (unsigned index = 0; index < 16; index++) {
      input >> token;
      vectors[index]->Low = value(token, entry);
      vectors[index]->High = vectors[index]->Low ^ 0x5555555555555555ull;
    }
    bool bounded = context.Rsp >= (DWORD64)stack && context.Rsp < (DWORD64)(stack + sizeof(stack));
    for (unsigned index = 0; index < memoryCount; index++) {
      long long address;
      unsigned size;
      input >> address >> size >> token;
      if (address < -(long long)sizeof(stack) / 2 || size > sizeof(stack) ||
        address > (long long)sizeof(stack) / 2 - size) { bounded = false; continue; }
      unsigned char *destination = (unsigned char *)(entry + address);
      const DWORD64 low = value(token, entry);
      const DWORD64 high = low ^ 0x5555555555555555ull;
      for (unsigned byte = 0; byte < size; byte++) {
        destination[byte] = (unsigned char)(((byte / 8) % 2 ? high : low) >> ((byte % 8) * 8));
      }
    }
    if (!image || !bounded) {
      std::printf("{\"id\":%u,\"status\":\"unavailable\"}\n", id);
      continue;
    }
    RUNTIME_FUNCTION runtime = { begin, end, info };
    context.Rip = (DWORD64)image + begin + offset;
    const DWORD fault = unwind((DWORD64)image, context.Rip, &runtime, &context);
    const bool rspCorrect = context.Rsp == entry + 8;
    const bool ripCorrect = context.Rip == returnAddress;
    unsigned wrongMask = 0;
    for (unsigned index = 0; index < 16; index++) {
      if ((mask & (1u << index)) && *registers[index] != original(index)) wrongMask |= 1u << index;
      if ((mask & (1u << (16 + index))) && (vectors[index]->Low != original(16 + index) ||
        (DWORD64)vectors[index]->High != (original(16 + index) ^ 0x5555555555555555ull))) wrongMask |= 1u << (16 + index);
    }
    const bool correct = rspCorrect && ripCorrect && wrongMask == 0;
    std::printf("{\"id\":%u,\"status\":\"%s\",\"fault\":%lu,\"rspDelta\":%lld,"
      "\"rspOk\":%s,\"ripOk\":%s,\"wrongMask\":%u}\n", id,
      fault ? "fault" : correct ? "agrees" : "differs", fault, (long long)(context.Rsp - entry),
      rspCorrect ? "true" : "false", ripCorrect ? "true" : "false", wrongMask);
  }
  if (image) UnmapViewOfFile(image);
  if (mapping) CloseHandle(mapping);
  if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
}
