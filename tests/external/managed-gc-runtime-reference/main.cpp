#include "host.h"
// Test-only cursor access; all decoding and root enumeration execute unmodified
// dotnet/runtime v10.0.0 C++ sources. Build v3 and v4 separately, as the
// runtime does.
#define private public
#include "gcinfodecoder.cpp"
#undef private
using Decoder = TGcInfoDecoder<AMD64GcInfoEncoding>;
struct Location {
  uintptr_t address;
  unsigned flags;
  uint32_t slot;
};
struct LiveRoots {
  std::vector<Location> locations;
  std::vector<uint32_t> live;
};
static void root(void *context, void **address, uint32_t flags) {
  auto &state = *(LiveRoots *)context;
  for (auto location : state.locations)
    if (location.address == (uintptr_t)address && location.flags == flags)
      state.live.push_back(location.slot);
}
static void word(uint32_t &hash, uint32_t value) {
  for (int i = 0; i < 4; i++) {
    hash ^= (value >> (8 * i)) & 255;
    hash *= 16777619U;
  }
}
static void points(Decoder *, uint32_t offset, void *context) {
  ((std::vector<uint32_t> *)context)->push_back(offset);
}
static bool interval(uint32_t start, uint32_t end, void *context) {
  ((std::vector<std::pair<uint32_t, uint32_t>> *)context)
      ->emplace_back(start, end);
  return false;
}
static void writeFrameLayout(Decoder &decoder) {
  if (decoder.m_headerFlags & 64)
    std::cout << ",\"stackBaseRegister\":" << decoder.GetStackBaseRegister();
  if (decoder.m_headerFlags & 256)
    std::cout << ",\"editAndContinueBytes\":"
              << decoder.GetSizeOfEditAndContinuePreservedArea();
  if (decoder.m_headerFlags & 512)
    std::cout << ",\"reversePInvokeStackOffset\":"
              << decoder.GetReversePInvokeFrameStackSlot();
}
static void writeHeader(Decoder &decoder, unsigned format, uint32_t version) {
  std::cout << "{\"header\":{\"flags\":" << decoder.m_headerFlags
            << ",\"codeLength\":" << decoder.GetCodeLength();
  if (version == 3)
    std::cout << ",\"returnKind\":" << decoder.GetReturnKind();
  if (decoder.m_headerFlags & 0x34)
    std::cout << ",\"validRange\":{\"startOffset\":"
              << decoder.m_ValidRangeStart
              << ",\"endOffset\":" << decoder.m_ValidRangeEnd << "}";
  if (decoder.m_headerFlags & 4)
    std::cout << ",\"cookieStackOffset\":" << decoder.GetGSCookieStackSlot();
  if (version == 3 && (decoder.m_headerFlags & 8))
    std::cout << ",\"parentStackOffset\":" << decoder.GetPSPSymStackSlot();
  if (decoder.m_headerFlags & 0x30)
    std::cout << ",\"genericContextStackOffset\":"
              << decoder.GetGenericsInstContextStackSlot();
  writeFrameLayout(decoder);
  if (format)
    std::cout << ",\"outgoingStackBytes\":"
              << decoder.GetSizeOfStackParameterArea();
}
static uint32_t
liveHash(GCInfoToken token, RegDisplay &display, LiveRoots &state,
         const std::vector<uint32_t> &safes,
         const std::vector<std::pair<uint32_t, uint32_t>> &ranges) {
  auto query = [&](uint32_t offset, uint32_t reportedOffset, uint32_t &hash) {
    Decoder current(
        token, (GcInfoDecoderFlags)(DECODE_GC_LIFETIMES | DECODE_NO_VALIDATION),
        offset);
    state.live.clear();
    current.EnumerateLiveSlots(
        &display, true, ActiveStackFrame | NoReportUntracked, root, &state);
    std::sort(state.live.begin(), state.live.end());
    word(hash, reportedOffset);
    for (auto slot : state.live)
      word(hash, slot);
    word(hash, 0xffffffff);
  };
  uint32_t hash = 2166136261U;
  for (auto offset : safes)
    query(offset - (token.Version < 4 ? 1 : 0), offset, hash);
  for (auto range : ranges)
    for (uint32_t offset = range.first; offset < range.second; offset++)
      query(offset, offset, hash);
  return hash;
}
static void writeSlots(Decoder &decoder,
                       GcSlotDecoder<AMD64GcInfoEncoding> &slots,
                       RegDisplay &display, LiveRoots &state) {
  for (uint32_t i = 0; i < slots.GetNumSlots(); i++) {
    const auto &slot = *slots.GetSlotDesc(i);
    bool reg = i < slots.GetNumRegisters();
    auto address =
        reg ? decoder.GetRegisterSlot(slot.Slot.RegisterNumber, &display)
            : decoder.GetStackSlot(slot.Slot.Stack.SpOffset,
                                   slot.Slot.Stack.Base, &display);
    if (i < slots.GetNumTracked())
      state.locations.push_back(
          {(uintptr_t)address, (unsigned)slot.Flags & 3, i});
    if (i)
      std::cout << ",";
    std::cout << "{\"kind\":\"" << (reg ? "register" : "stack")
              << "\",\"flags\":"
              << ((unsigned)slot.Flags | (i >= slots.GetNumTracked() ? 4 : 0));
    if (reg)
      std::cout << ",\"register\":" << slot.Slot.RegisterNumber;
    else
      std::cout << ",\"base\":" << slot.Slot.Stack.Base
                << ",\"offset\":" << slot.Slot.Stack.SpOffset;
    std::cout << "}";
  }
}
static void read(const std::vector<uint8_t> &bytes, uint32_t version) {
  GCInfoToken token{(void *)bytes.data(), version};
  Decoder decoder(token);
  std::vector<uint32_t> safes;
  std::vector<std::pair<uint32_t, uint32_t>> ranges;
  decoder.EnumerateSafePoints(points, &safes);
  decoder.EnumerateInterruptibleRanges(interval, &ranges);
  GcSlotDecoder<AMD64GcInfoEncoding> slots;
  slots.DecodeSlotTable(decoder.m_Reader);
  RegDisplay display{};
  uintptr_t registers[15];
  for (int i = 0; i < 15; i++) {
    registers[i] = 0x300000000ULL;
    (&display.pRax)[i] = &registers[i];
  }
  display.SP = 0x100000000ULL;
  LiveRoots state;
  writeHeader(decoder, bytes[0] & 1, version);
  std::cout << "},\"slots\":[";
  writeSlots(decoder, slots, display, state);
  std::cout << "],\"safePoints\":[";
  for (size_t i = 0; i < safes.size(); i++) {
    if (i)
      std::cout << ",";
    std::cout << safes[i] - (version < 4 ? 1 : 0);
  }
  std::cout << "],\"interruptibleRanges\":[";
  for (size_t i = 0; i < ranges.size(); i++) {
    if (i)
      std::cout << ",";
    std::cout << "{\"startOffset\":" << ranges[i].first
              << ",\"endOffset\":" << ranges[i].second << "}";
  }
  const auto hash = liveHash(token, display, state, safes, ranges);
  std::cout << "],\"liveHash\":\"" << std::hex << hash << std::dec << "\"}\n";
}
int main() {
  std::string line;
  while (std::getline(std::cin, line)) {
    std::istringstream input(line);
    uint32_t version;
    std::string hex;
    input >> version >> hex;
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.size(); i += 2)
      bytes.push_back((uint8_t)std::stoul(hex.substr(i, 2), nullptr, 16));
    bytes.resize(bytes.size() +
                 16); // The runtime bit reader prefetches aligned native words.
    read(bytes, version);
  }
}
