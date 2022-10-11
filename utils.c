#include <stdio.h>
#include <stdarg.h>
#include "utils.h"

void reportError_(const char *file, size_t line, const char *format, ...)
{
    fprintf(stderr, "ERROR :: ");

    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    fprintf(stderr, "(Error reported at %s:%ld)\n", file, line);
}
