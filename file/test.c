#include "hash.h"
#include "encode.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <zconf.h>
#include <ec.h>
#include <string.h>

#define DIGEST "sha1"

int main()
{
    FILE* f1 = fopen("testfile1", "w+");
    FILE* f2 = fopen("testfile2", "w+");
    assert(f1 != NULL);
    assert(f2 != NULL);
    fprintf(f1, "message1");
    fprintf(f2, "message2");
    fclose(f1);
    fclose(f2);
    unsigned char hash1[hash_size(DIGEST)];
    unsigned char hash2[hash_size(DIGEST)];
    memset(hash1, 0, sizeof(hash1));
    memset(hash2, 0, sizeof(hash2));
    int err = hash("testfile1", DIGEST, hash1);
    if(err != ERROR_SUCCESS)
    {
        abort();
    }
    err = hash("testfile2", DIGEST, hash2);
    if(err != ERROR_SUCCESS)
    {
        abort();
    }
    assert(memcmp(hash1, hash2, sizeof(hash1)) != 0);
    unlink("testfile1");
    unlink("testfile2");

    char b64hash1[encoded_size(sizeof(hash1))];
    char b64hash2[encoded_size(sizeof(hash2))];
    memset(b64hash1, 1, sizeof(b64hash1));
    memset(b64hash2, 1, sizeof(b64hash2));
    err = encode(hash1, sizeof(hash1), b64hash1);
    if(err != ERROR_SUCCESS)
    {
        abort();
    }
    err = encode(hash2, sizeof(hash2), b64hash2);
    if(err != ERROR_SUCCESS)
    {
        abort();
    }
    assert(memcmp(b64hash1, b64hash2, sizeof(hash1)) != 0);

    return 0;
}
