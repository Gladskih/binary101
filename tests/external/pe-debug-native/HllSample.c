// Open Watcom wcc386 -bt=nt -d2 -hc -s emits OMF with CodeView C7 streams.
// wlink "format windows nt" "debug hll" packages these unchanged in NB04,
// with a module style/version of zero and a terminal trailer outside PE sections.
// This is a mixed container fixture, not IBM-compiler HLL record output.
struct PublicState { int count; };
int exported;
int __cdecl entry(void) {
    struct PublicState state;
    state.count = exported;
    return state.count;
}
