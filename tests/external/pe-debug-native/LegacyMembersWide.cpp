// MSVC /Z7 /utf-8 fixture for CodeView with 32-bit type indices.
// The non-ASCII member deliberately checks UTF-8 name preservation against LLVM.
struct Packet {
    int count;
    double ratio;
    int длина;
    static int total;
    enum class Mode { first = 1, last = 7 };
    int read() const { return count + длина; }
};

int Packet::total = 0;
Packet packet;

int entry() {
    packet.count = 1;
    packet.длина = 7;
    return packet.read();
}
