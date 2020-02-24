#ifndef MINIVCS_ENCODE_H
#define MINIVCS_ENCODE_H

#include <stddef.h>

extern int encode(const char* src, size_t size, char* dest);

extern size_t encoded_size(size_t size);

#endif //MINIVCS_ENCODE_H
