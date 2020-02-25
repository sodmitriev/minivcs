#ifndef MINIVCS_ENCODE_H
#define MINIVCS_ENCODE_H

#include <stddef.h>

extern int encode(const char* src, size_t size, char* dest);

extern size_t encoded_size(size_t size);

#define ENCODE(value, size, err)                                    \
    char* value##_encoded = malloc(encoded_size(size));             \
    if(!value##_encoded)                                            \
    {                                                               \
        return ERROR_SYSTEM;                                        \
    }                                                               \
    err = encode(value, size, value##_encoded);                     \
    if(err != ERROR_SUCCESS)                                        \
    {                                                               \
        free(value##_encoded);                                      \
    }                                                               \
    (void)(0)

#endif //MINIVCS_ENCODE_H
