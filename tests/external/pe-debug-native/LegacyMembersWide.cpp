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
