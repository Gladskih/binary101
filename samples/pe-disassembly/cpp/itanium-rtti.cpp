#include <typeinfo>

struct Base {
  virtual ~Base() = default;
  virtual int value() const { return 1; }
};
struct Derived : Base { int value() const override { return 2; } };
struct Side { virtual ~Side() = default; };
struct Multiple : Derived, Side {};
struct Virtual : virtual Base { int value() const override { return 3; } };
struct EmptyA {};
struct EmptyB {};
struct Collision : private EmptyA, private EmptyB {
  virtual int value() const { return 4; }
};
Collision collision;
struct RttiOnly : private EmptyA, private EmptyB {};
const std::type_info* forceRtti = &typeid(RttiOnly);

int main(int argc, char**) {
  Derived derived;
  Multiple multiple;
  Virtual virtualBase;
  Base* selected = argc > 2 ? static_cast<Base*>(&multiple) :
    argc > 1 ? static_cast<Base*>(&virtualBase) : &derived;
  return selected->value() + (typeid(*selected) == typeid(Derived)) + collision.value();
}
