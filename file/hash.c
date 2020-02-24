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
    EVP_DigestInit_ex(mdctx, md, NULL);

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
        EVP_DigestUpdate(mdctx, buf, len);
    }

    if(ferror(src))
    {
        EVP_MD_CTX_free(mdctx);
        fclose(src);
        return ERROR_SYSTEM;
    }

    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    memcpy(ret, md_value, md_len);

    return 0;
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
