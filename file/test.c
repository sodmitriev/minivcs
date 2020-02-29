#include "hash.h"
#include "encode.h"
#include "crypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <zconf.h>
#include <ec.h>
#include <string.h>

#define DIGEST "sha1"

int main()
{
    //Hash + encode
    {
        FILE *f1 = fopen("testfile1", "w+");
        FILE *f2 = fopen("testfile2", "w+");
        assert(f1 != NULL);
        assert(f2 != NULL);
        fprintf(f1, "message1");
        fprintf(f2, "message2");
        fclose(f1);
        fclose(f2);
        size_t hsize;
        if(hash_size(DIGEST, &hsize) != ERROR_SUCCESS)
        {
            abort();
        }
        unsigned char hash1[hsize];
        unsigned char hash2[hsize];
        memset(hash1, 0, sizeof(hash1));
        memset(hash2, 0, sizeof(hash2));
        int err = hash("testfile1", DIGEST, hash1);
        if (err != ERROR_SUCCESS)
        {
            abort();
        }
        err = hash("testfile2", DIGEST, hash2);
        if (err != ERROR_SUCCESS)
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
        if (err != ERROR_SUCCESS)
        {
            abort();
        }
        err = encode(hash2, sizeof(hash2), b64hash2);
        if (err != ERROR_SUCCESS)
        {
            abort();
        }
        assert(memcmp(b64hash1, b64hash2, sizeof(hash1)) != 0);
    }

    //Crypto
    {
        const char msg[] = "0000000000000000"
                           "1111111111111111"
                           "2222222222222222"
                           "3333333333333333"
                           "4444444444444444"
                           "5555555555555555"
                           "6666666666666666"
                           "7777777777777777"
                           "8888888888888888"
                           "9999999999999999"
                           "aaaaaaaaaaaaaaaa"
                           "bbbbbbbbbbbbbbbb"
                           "cccccccccccccccc"
                           "dddddddddddddddd"
                           "eeeeeeeeeeeeeeee"
                           "fffffff";
        FILE *f = fopen("testfile", "w+");
        fprintf(f, msg);
        fclose(f);
        if(encrypt_file("testfile", "testfile.ECRYPTED", "mykey", "aes-256-cbc", "sha1"))
        {
            abort();
        }
        unlink("testfile");
        if(decrypt_file("testfile.ECRYPTED", "testfile", "mykey", "aes-256-cbc", "sha1"))
        {
            abort();
        }
        f = fopen("testfile", "r");
        char buf[1024];
        fscanf(f, "%s", buf);
        if(strcmp(buf, msg) != 0)
        {
            abort();
        }

        struct file_encrypted* file = file_encrypted_new();
        assert(file);

        if(file_encrypted_open("testfile.ECRYPTED", "w", "mykey", "aes-256-cbc", "sha1", file))
        {
            abort();
        }
        size_t sizeo;
        if(file_encrypted_write(msg, 4, &sizeo, file))
        {
            abort();
        }
        assert(sizeo == 4);
        if(file_encrypted_write(msg + 4, sizeof(msg) - 4, &sizeo, file))
        {
            abort();
        }
        file_encrypted_close(file);

        if(file_encrypted_open("testfile.ECRYPTED", "r", "mykey", "aes-256-cbc", "sha1", file))
        {
            abort();
        }
        memset(buf, 0, sizeof(buf));
        if(file_encrypted_read(buf, 4, &sizeo, file))
        {
            abort();
        }
        assert(sizeo == 4);
        if(file_encrypted_read(buf + 4, sizeof(buf) - 4, &sizeo, file))
        {
            abort();
        }
        file_encrypted_close(file);
        file_encrypted_delete(file);
        if(memcmp(buf, msg, sizeof(msg) - 1) != 0)
        {
            abort();
        }
    }

    return 0;
}
