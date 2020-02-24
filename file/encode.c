#include "encode.h"
#include "eccrypto.h"
#include <ec.h>
#include <stddef.h>
#include <string.h>
#include <openssl/evp.h>

extern int encode(const char* src, size_t size, char* dest)
{
    if(EVP_EncodeBlock(dest, src, size) == 0)
    {
        return ERROR_CRYPTO;
    }

    return ERROR_SUCCESS;
}

extern size_t encoded_size(size_t size)
{
    if(size == 0)
    {
        return 1;
    }
    return 4 * (((size - 1) / 3) + 1) + 1;
}


