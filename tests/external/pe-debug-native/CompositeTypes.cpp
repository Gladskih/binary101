enum class State : unsigned short { idle = 1, ready = 7 };

union Choice {
    int count;
    double ratio;
};

struct Base {
    int tag;
    virtual int read() const { return tag; }
    virtual int read(int extra) const { return tag + extra; }
    virtual int tagValue() const { return tag; }
};

struct Packet : virtual Base {
    int count;
    int values[3];
    Choice choice;
    State state;

    int read() const override { return count; }
    int read(int extra) const { return count + extra; }
};

Packet sample;

extern "C" int inspect(Packet *packet) {
    return packet->read() + packet->read(2) + packet->values[1];
}
