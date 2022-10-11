#include "utils.h"

typedef struct { 
    uint8_t bytes[6]; 
} MACAddress;

typedef uint32_t IPAddress;

_Static_assert(sizeof(IPAddress) == 4,  "??? :)");
_Static_assert(sizeof(MACAddress) == 6, "Struct was packed in an unexpected way");
