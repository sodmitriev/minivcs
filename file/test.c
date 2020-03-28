#include "operations.h"

#include <sys/random.h>
#include <stdlib.h>
#include <CTransform/CEasyException/exception.h>
#include <zconf.h>

#define CHECK(x)\
{\
    if(!(x))\
        abort();\
} ((void)(0))

#define HANDLE_EXCEPTION()                                          \
if(EXCEPTION_IS_THROWN)                                             \
{                                                                   \
    fprintf(stderr, "%d : %s\n", EXCEPTION_ERROR, EXCEPTION_MSG);   \
    abort();                                                        \
} ((void)(0))

#define FILE_NAME_RAW_LEN 160

int main()
{
    struct config config;
    config_init("test_config", &config);

    config_set("file_digest", "sha1", &config);
    config_set("key_digest", "sha1", &config);
    config_set("file_cipher", "aes-256-cbc", &config);
    config_set("compression_level", "5", &config);


    EXCEPTION_CLEAR();

    //File name
    {
        unsigned char buf[FILE_NAME_RAW_LEN];
        ssize_t ret = getrandom(buf, sizeof(buf), 0);
        CHECK(ret == sizeof(buf));
        size_t size = file_get_name_length(sizeof(buf));
        CHECK(((size - 1) / 4) * 3 >= sizeof(buf) && (((size - 1) / 4) - 1) * 3 <= sizeof(buf));
        char name[size];
        file_get_name(buf, sizeof(buf), name);
        HANDLE_EXCEPTION();
        CHECK(strlen(name) == size - 1);
        char* end = name + size - 1;
        char* ptr;
        for(ptr = name; ptr != end && *ptr != '='; ++ptr)
        {
            CHECK((*ptr >= 'A' && *ptr <= 'Z') || (*ptr >= 'a' && *ptr <= 'z') || (*ptr >= '0' && *ptr <= '9') ||
                      *ptr == '+' || *ptr == '_');
        }
        for(; ptr != end; ++ptr)
        {
            CHECK(*ptr == '=');
        }
    }

    //Hash
    {
        const char msg1[] = "message1";
        const char msg2[] = "message2";
        {
            FILE *f = fopen("test1", "w");
            CHECK(f);
            size_t ret = fwrite(msg1, 1, sizeof(msg1), f);
            CHECK(ret == sizeof(msg1));
            fclose(f);
            f = fopen("test2", "w");
            ret = fwrite(msg2, 1, sizeof(msg2), f);
            CHECK(ret == sizeof(msg2));
            fclose(f);
            f = fopen("test3", "w");
            ret = fwrite(msg1, 1, sizeof(msg1), f);
            CHECK(ret == sizeof(msg1));
            fclose(f);
        }

        size_t size = file_hash_size(&config);
        HANDLE_EXCEPTION();

        unsigned char hash1[size];
        unsigned char hash2[size];
        unsigned char hash3[size];

        memset(hash1, '1', size);
        memset(hash2, '1', size);
        memset(hash3, '2', size);

        file_hash("test1", &config, hash1);
        HANDLE_EXCEPTION();
        file_hash("test2", &config, hash2);
        HANDLE_EXCEPTION();
        file_hash("test3", &config, hash3);
        HANDLE_EXCEPTION();

        CHECK(memcmp(hash1, hash2, size) != 0);
        CHECK(memcmp(hash1, hash3, size) == 0);

        unlink("test1");
        unlink("test2");
        unlink("test3");
    }

    //Store and extract
    {
        const char msg[] = "message";
        {
            FILE *f = fopen("test", "w");
            CHECK(f);
            size_t ret = fwrite(msg, 1, sizeof(msg) - 1, f);
            CHECK(ret == sizeof(msg) - 1);
            fclose(f);
        }
        file_store("test", "test_stored", "mykey", &config);
        HANDLE_EXCEPTION();

        file_extract("test_stored", "test_out", "mykey", &config);
        HANDLE_EXCEPTION();

        CHECK(system("diff test test_out") == 0);
    }

    config_destroy(&config);
    unlink("test_config");

    return 0;
}
