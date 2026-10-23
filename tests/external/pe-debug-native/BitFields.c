struct BitFields {
    unsigned int ready : 1;
    unsigned int mode : 3;
    signed int delta : 5;
};

struct BitFields sample = { 1, 5, -3 };
