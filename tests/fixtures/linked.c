/* Compiler-produced input for loader and symbol-table smoke tests. */
#ifdef _WIN32
#include <windows.h>
#define EXPORT __declspec(dllexport)
static unsigned imported_value(void) {
    return GetCurrentProcessId();
}
#else
#define EXPORT __attribute__((visibility("default")))
extern unsigned fixture_external_value(void);
static unsigned imported_value(void) {
    return fixture_external_value();
}
#endif

EXPORT unsigned fixture_adjust(unsigned input) {
    unsigned offset = imported_value();
    return input > 9 ? input - offset : input + offset;
}
