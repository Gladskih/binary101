// DMD 2.100.2 -m32omf -g emits a genuine PE with embedded legacy NB09 CodeView.
// This exercises old member records; the MSVC .cpp fixture covers modern records.
module legacy_members;

struct Packet {
    int count;
    double ratio;
}

enum Mode { first = 1, last = 7 }

class Container {
    int value;
    this(int initial) { value = initial; }
    int read() { return value; }
}

Packet sharedPacket;
Mode sharedMode;

int main() {
    Packet local;
    local.count = 41;
    local.ratio = 2.0;
    auto item = new Container(local.count);
    sharedPacket = local;
    sharedMode = Mode.last;
    return item.read() == 41 ? 0 : 1;
}
