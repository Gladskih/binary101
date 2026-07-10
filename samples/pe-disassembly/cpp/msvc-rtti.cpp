#include <typeinfo>

namespace Binary101RttiFixture {

class SimpleBase {
public:
    virtual ~SimpleBase() = default;
    virtual int first() const { return 11; }
    virtual int second() const { return 13; }
};

class SingleDerived final : public SimpleBase {
public:
    int first() const override { return 17; }
    int second() const override { return 19; }
};

class LeftBase {
public:
    virtual ~LeftBase() = default;
    virtual int left() const { return 23; }
};

class RightBase {
public:
    virtual ~RightBase() = default;
    virtual int right() const { return 29; }
};

class MultipleDerived final : public LeftBase, public RightBase {
public:
    int left() const override { return 31; }
    int right() const override { return 37; }
    virtual int own() const { return 41; }
};

class VirtualBase {
public:
    virtual ~VirtualBase() = default;
    virtual int root() const { return 43; }
};

class VirtualLeft : virtual public VirtualBase {
public:
    int root() const override { return 47; }
    virtual int virtualLeft() const { return 53; }
};

class VirtualRight : virtual public VirtualBase {
public:
    int root() const override { return 59; }
    virtual int virtualRight() const { return 61; }
};

class VirtualDiamond final : public VirtualLeft, public VirtualRight {
public:
    int root() const override { return 67; }
    int virtualLeft() const override { return 71; }
    int virtualRight() const override { return 73; }
};

__declspec(noinline) int callSimple(SimpleBase& value) {
    return value.first() + value.second();
}

__declspec(noinline) int callLeft(LeftBase& value) {
    return value.left();
}

__declspec(noinline) int callRight(RightBase& value) {
    return value.right();
}

__declspec(noinline) int callVirtualRoot(VirtualBase& value) {
    return value.root();
}

__declspec(noinline) int crossCast(LeftBase& value) {
    const auto* right = dynamic_cast<RightBase*>(&value);
    return right ? right->right() : 0;
}

__declspec(noinline) int identify(SimpleBase& value) {
    return typeid(value) == typeid(SingleDerived) ? 79 : 0;
}

} // namespace Binary101RttiFixture

int main() {
    using namespace Binary101RttiFixture;
    SimpleBase simple;
    SingleDerived single;
    LeftBase left;
    RightBase right;
    MultipleDerived multiple;
    VirtualBase virtualBase;
    VirtualLeft virtualLeft;
    VirtualRight virtualRight;
    VirtualDiamond diamond;
    return callSimple(simple) + callSimple(single) + callLeft(left) + callRight(right) +
        callLeft(multiple) + callRight(multiple) + crossCast(multiple) + identify(single) +
        callVirtualRoot(virtualBase) + callVirtualRoot(virtualLeft) +
        callVirtualRoot(virtualRight) + callVirtualRoot(diamond);
}
