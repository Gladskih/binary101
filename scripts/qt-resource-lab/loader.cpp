#include <cstdio>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

int main(int count, char **arguments)
{
    if (count != 2 && count != 3) return 2;
#ifdef _WIN32
    const HMODULE module = LoadLibraryA(arguments[1]);
    if (!module) return 3;
    const auto probe = reinterpret_cast<const char *(*)()>(GetProcAddress(module, "lab_probe"));
    const auto validate = reinterpret_cast<const char *(*)(const char *)>(GetProcAddress(module, "lab_validate_file"));
#else
    void *module = dlopen(arguments[1], RTLD_NOW | RTLD_LOCAL);
    if (!module) { std::fprintf(stderr, "%s\n", dlerror()); return 3; }
    const auto probe = reinterpret_cast<const char *(*)()>(dlsym(module, "lab_probe"));
    const auto validate = reinterpret_cast<const char *(*)(const char *)>(dlsym(module, "lab_validate_file"));
#endif
    if (!probe || !validate) return 4;
    std::puts(count == 3 ? validate(arguments[2]) : probe());
    return 0;
}
