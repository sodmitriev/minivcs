#ifndef MINIVCS_HASH_H
#define MINIVCS_HASH_H

#include <stddef.h>
#include "eccrypto.h"

extern int hash(const char* file, const char* digest, unsigned char* ret);

extern int hash_size(const char* digest, size_t* out);

#endif //MINIVCS_HASH_H
