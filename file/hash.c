#include "hash.h"
#include <openssl/evp.h>
#include <ec.h>
#include <string.h>

#define BUFFER_SIZE 512

int hash(const char* file, const char* digest, unsigned char* ret)
{
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    int md_len;

    md = EVP_get_digestbyname(digest);

    if(!md)
    {
        return ERROR_NOTFOUND;
    }

    mdctx = EVP_MD_CTX_new();
    if(mdctx == NULL)
    {
        return ERROR_NOMEM;
    }
    if(EVP_DigestInit_ex(mdctx, md, NULL) == 0)
    {
        EVP_MD_CTX_free(mdctx);
        return ERROR_CRYPTO;
    }

    FILE* src = fopen(file, "r");
    if(src == NULL)
    {
        EVP_MD_CTX_free(mdctx);
        return ERROR_SYSTEM;
    }

    char buf[BUFFER_SIZE];

    size_t len;
    while((len = fread(buf, sizeof(*buf), sizeof(buf) / sizeof(*buf), src)))
    {
        if(EVP_DigestUpdate(mdctx, buf, len) == 0)
        {
            EVP_MD_CTX_free(mdctx);
            fclose(src);
            return ERROR_CRYPTO;
        }
    }

    if(ferror(src))
    {
        EVP_MD_CTX_free(mdctx);
        fclose(src);
        return ERROR_SYSTEM;
    }

    if(EVP_DigestFinal_ex(mdctx, md_value, &md_len) == 0)
    {
        EVP_MD_CTX_free(mdctx);
        fclose(src);
        return ERROR_CRYPTO;
    }

    EVP_MD_CTX_free(mdctx);
    fclose(src);

    memcpy(ret, md_value, md_len);

    return ERROR_SUCCESS;
}

extern int hash_size(const char* digest)
{

    const EVP_MD *md;

    md = EVP_get_digestbyname(digest);

    if(!md)
    {
        return ERROR_NOTFOUND;
    }

    return EVP_MD_size(md);
}
