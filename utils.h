#include <stddef.h>

#define PACKED __attribute__((packed))

void reportError_(const char *file, size_t line, const char *format, ...);

#define reportError(format, ...) \
    reportError_(__FILE__, __LINE__, format, ##__VA_ARGS__)
