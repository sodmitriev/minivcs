#include "operations.h"

#include <errno.h>

#include <CTransform/controller.h>
#include <CTransform/read_write/source_write.h>
#include <CTransform/read_write/sink_read.h>
#include <CTransform/file/source_file.h>
#include <CTransform/file/sink_file.h>
#include <CTransform/encode/transformation_b64_encode.h>
#include <CTransform/util/transformation_replace.h>
#include <CTransform/crypto/transformation_hash.h>
#include <CTransform/crypto/transformation_encrypt.h>
#include <CTransform/crypto/transformation_decrypt.h>
#include <CTransform/compress/transformation_compress.h>
#include <CTransform/compress/transformation_decompress.h>

#include <openssl/evp.h>

#define HANDLE_EXCEPTION(lable) if(EXCEPTION_IS_THROWN) goto lable; ((void)(0))

static size_t digest_hash_size(const char* digest)
{
    const EVP_MD *md;

    md = EVP_get_digestbyname(digest);

    if(!md)
    {
        EXCEPTION_THROW(EINVAL, "File digest \"%s\" does not exist", digest);
        return -1;
    }
    return EVP_MD_size(md);
}

void file_hash(const char* path, const struct config* conf, unsigned char* hash)
{

    assert(conf);
    const char* digest = config_get("file_digest", conf);
    if(!digest)
    {
        EXCEPTION_THROW(EINVAL, "%s", "\"file_digest\" is not specified");
        return;
    }

    size_t out_size = digest_hash_size(digest);
    HANDLE_EXCEPTION(cleanup_exit);

    controller ctl;
    transformation_hash hasht;

    source_file in;
    sink_read out;

    controller_constructor(&ctl);
    HANDLE_EXCEPTION(cleanup_exit);

    transformation_hash_constructor(digest, &hasht);
    HANDLE_EXCEPTION(cleanup_ctl);

    controller_add_transformation((transformation*) &hasht, &ctl);
    HANDLE_EXCEPTION(cleanup_hasht);

    source_file_constructor(&in);
    HANDLE_EXCEPTION(cleanup_hasht);

    source_file_open(path, &in);
    HANDLE_EXCEPTION(cleanup_in);

    sink_read_constructor(&out);
    HANDLE_EXCEPTION(cleanup_in);

    sink_read_set(hash, 1, out_size, &out);
    HANDLE_EXCEPTION(cleanup_out);

    controller_set_source((source*) &in, &ctl);
    controller_set_sink((sink*) &out, &ctl);

    controller_finalize(&ctl);
    HANDLE_EXCEPTION(cleanup_out);
    assert((controller_get_stage(&ctl) == controller_stage_done && sink_read_get_result(&out) == out_size ));

    cleanup_out:
    sink_destructor((sink*) &out);
    cleanup_in:
    source_destructor((source*) &in);
    cleanup_hasht:
    transformation_destructor((transformation*) &hasht);
    cleanup_ctl:
    controller_destructor(&ctl);
    cleanup_exit:
    ((void)(0));
}

size_t file_hash_size(const struct config* conf)
{
    assert(conf);
    const char* digest = config_get("file_digest", conf);
    if(!digest)
    {
        EXCEPTION_THROW(EINVAL, "%s", "\"file_digest\" is not specified");
        return -1;
    }

    return digest_hash_size(digest);
}

typedef struct
{
    int compression_level;
    const char* key_digest;
    const char* file_cipher;
} file_transform_info;

static file_transform_info get_transform_info(const struct config* conf)
{
    file_transform_info ret = {0, NULL, NULL};

    {
        size_t compression_level;
        const char *compression_level_str = config_get("compression_level", conf);
        if(!compression_level_str || compression_level_str[0] == '\0' || strcmp(compression_level_str, "none") == 0)
        {
            compression_level = 0;
        }
        else
        {
            errno = 0;
            char* end = NULL;
            compression_level = strtoul(compression_level_str, &end, 10);
            if(end == compression_level_str || errno || compression_level > INT_MAX)
            {
                if(errno == 0)
                {
                    errno = EINVAL;
                }
                EXCEPTION_THROW(errno, "Invalid compression level \"%s\"", compression_level_str);
                return ret;
            }
        }
        ret.compression_level = (int) compression_level;
    }

    ret.file_cipher = config_get("file_cipher", conf);
    if(ret.file_cipher)
    {
        if(ret.file_cipher[0] == '\0' || strcmp(ret.file_cipher, "none") == 0)
        {
            ret.file_cipher = NULL;
        }
        else
        {
            ret.key_digest = config_get("key_digest", conf);
            if(!ret.key_digest || ret.key_digest[0] == '\0' || strcmp(ret.key_digest, "none") == 0)
            {
                EXCEPTION_THROW(EINVAL, "%s", "\"key_digest\" is not set but encryption is enabled");
                return ret;
            }
        }
    }
    return ret;
}

void file_store(const char* src, const char* dest, const char* key, const struct config* conf)
{
    file_transform_info ret = get_transform_info(conf);
    HANDLE_EXCEPTION(cleanup_exit);

    controller ctl;
    transformation_compress compress;
    transformation_encrypt encrypt;

    source_file in;
    sink_file out;

    controller_constructor(&ctl);
    HANDLE_EXCEPTION(cleanup_exit);

    if(ret.compression_level > 0)
    {
        transformation_compress_constructor((int) ret.compression_level, &compress);
        HANDLE_EXCEPTION(cleanup_ctl);

        controller_add_transformation((transformation*) &compress, &ctl);
        HANDLE_EXCEPTION(cleanup_compress);
    }

    if(ret.file_cipher)
    {
        transformation_encrypt_constructor(ret.file_cipher, ret.key_digest, key, &encrypt);
        HANDLE_EXCEPTION(cleanup_compress);

        controller_add_transformation((transformation*) &encrypt, &ctl);
        HANDLE_EXCEPTION(cleanup_encrypt);
    }

    source_file_constructor(&in);
    HANDLE_EXCEPTION(cleanup_encrypt);

    source_file_open(src, &in);
    HANDLE_EXCEPTION(cleanup_in);

    sink_file_constructor(&out);
    HANDLE_EXCEPTION(cleanup_in);

    sink_file_open(dest, &out);
    HANDLE_EXCEPTION(cleanup_out);

    controller_set_source((source*) &in, &ctl);
    controller_set_sink((sink*) &out, &ctl);

    controller_finalize(&ctl);
    HANDLE_EXCEPTION(cleanup_out);

    cleanup_out:
    sink_destructor((sink*) &out);
    cleanup_in:
    source_destructor((source*) &in);
    cleanup_encrypt:
    if(ret.file_cipher)
        transformation_destructor((transformation*) &encrypt);
    cleanup_compress:
    if(ret.compression_level > 0)
        transformation_destructor((transformation*) &compress);
    cleanup_ctl:
    controller_destructor(&ctl);
    cleanup_exit:
    ((void)(0));
}

void file_extract(const char* src, const char* dest, const char* key, const struct config* conf)
{
    file_transform_info ret = get_transform_info(conf);
    HANDLE_EXCEPTION(cleanup_exit);

    controller ctl;
    transformation_decompress decompress;
    transformation_decrypt decrypt;

    source_file in;
    sink_file out;

    controller_constructor(&ctl);
    HANDLE_EXCEPTION(cleanup_exit);

    if(ret.file_cipher)
    {
        transformation_decrypt_constructor(ret.file_cipher, ret.key_digest, key, &decrypt);
        HANDLE_EXCEPTION(cleanup_compress);

        controller_add_transformation((transformation*) &decrypt, &ctl);
        HANDLE_EXCEPTION(cleanup_encrypt);
    }

    if(ret.compression_level > 0)
    {
        transformation_decompress_constructor(&decompress);
        HANDLE_EXCEPTION(cleanup_ctl);

        controller_add_transformation((transformation*) &decompress, &ctl);
        HANDLE_EXCEPTION(cleanup_compress);
    }

    source_file_constructor(&in);
    HANDLE_EXCEPTION(cleanup_encrypt);

    source_file_open(src, &in);
    HANDLE_EXCEPTION(cleanup_in);

    sink_file_constructor(&out);
    HANDLE_EXCEPTION(cleanup_in);

    sink_file_open(dest, &out);
    HANDLE_EXCEPTION(cleanup_out);

    controller_set_source((source*) &in, &ctl);
    controller_set_sink((sink*) &out, &ctl);

    controller_finalize(&ctl);
    HANDLE_EXCEPTION(cleanup_out);

    cleanup_out:
    sink_destructor((sink*) &out);
    cleanup_in:
    source_destructor((source*) &in);
    cleanup_compress:
    if(ret.compression_level > 0)
        transformation_destructor((transformation*) &decompress);
    cleanup_encrypt:
    if(ret.file_cipher)
        transformation_destructor((transformation*) &decrypt);
    cleanup_ctl:
    controller_destructor(&ctl);
    cleanup_exit:
    ((void)(0));
}

void file_get_name(const unsigned char* raw, size_t raw_size, char* name)
{
    size_t out_size = file_get_name_length(raw_size);

    controller ctl;
    transformation_b64_encode encode;
    transformation_replace replace;

    source_write in;
    sink_read out;

    controller_constructor(&ctl);
    HANDLE_EXCEPTION(cleanup_exit);

    transformation_b64_encode_constructor(&encode);
    HANDLE_EXCEPTION(cleanup_ctl);

    controller_add_transformation((transformation*) &encode, &ctl);
    HANDLE_EXCEPTION(cleanup_encode);

    transformation_replace_constructor("/", 1, '_', &replace);
    HANDLE_EXCEPTION(cleanup_encode);

    controller_add_transformation((transformation*) &replace, &ctl);
    HANDLE_EXCEPTION(cleanup_replace);

    source_write_constructor(&in);
    HANDLE_EXCEPTION(cleanup_replace);

    sink_read_constructor(&out);
    HANDLE_EXCEPTION(cleanup_in);

    source_write_set(raw, 1, raw_size, &in);
    sink_read_set(name, 1, out_size, &out);

    controller_set_source((source*) &in, &ctl);
    controller_set_sink((sink*) &out, &ctl);

    controller_finalize(&ctl);
    HANDLE_EXCEPTION(cleanup_out);

    assert((controller_get_stage(&ctl) == controller_stage_done && sink_read_get_result(&out) == out_size - 1));

    name[out_size - 1] = '\0';

    cleanup_out:
    sink_destructor((sink*) &out);
    cleanup_in:
    source_destructor((source*) &in);
    cleanup_replace:
    transformation_destructor((transformation*) &replace);
    cleanup_encode:
    transformation_destructor((transformation*) &encode);
    cleanup_ctl:
    controller_destructor(&ctl);
    cleanup_exit:
    ((void)(0));
}

size_t file_get_name_length(size_t raw_size)
{
    if(raw_size == 0)
    {
        return 1;
    }
    return 4 * (((raw_size - 1) / 3) + 1) + 1;
}
