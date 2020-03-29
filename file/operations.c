#include "operations.h"
#include "file_transformation_controller.h"

#include <errno.h>

#include <CTransform/controller.h>
#include <CTransform/read_write/source_write.h>
#include <CTransform/read_write/sink_read.h>
#include <CTransform/file/source_file.h>
#include <CTransform/file/sink_file.h>
#include <CTransform/encode/transformation_b64_encode.h>
#include <CTransform/util/transformation_replace.h>
#include <CTransform/crypto/transformation_hash.h>

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

static void file_transfer(const char* src, const char* dest, controller* ctl)
{
    source_file in;
    sink_file out;

    source_file_constructor(&in);
    HANDLE_EXCEPTION(cleanup_exit);

    source_file_open(src, &in);
    HANDLE_EXCEPTION(cleanup_in);

    sink_file_constructor(&out);
    HANDLE_EXCEPTION(cleanup_in);

    sink_file_open(dest, &out);
    HANDLE_EXCEPTION(cleanup_out);

    controller_set_source((source*) &in, (controller*) ctl);
    controller_set_sink((sink*) &out, (controller*) ctl);

    controller_finalize((controller*) ctl);
    HANDLE_EXCEPTION(cleanup_out);

    cleanup_out:
    sink_destructor((sink*) &out);
    cleanup_in:
    source_destructor((source*) &in);
    cleanup_exit:
    ((void)(0));
}

void file_store(const char* src, const char* dest, const ftransform_ctx* ctx)
{
    ftransform_store_ctl ctl;

    ftransform_store_ctl_constructor(ctx, &ctl);
    HANDLE_EXCEPTION(cleanup_exit);
    file_transfer(src, dest, (controller*) &ctl);
    HANDLE_EXCEPTION(cleanup_ctl);

    cleanup_ctl:
    ftransform_store_ctl_destructor(&ctl);
    cleanup_exit:
    ((void)(0));
}

void file_extract(const char* src, const char* dest, const ftransform_ctx* ctx)
{
    ftransform_extract_ctl ctl;

    ftransform_extract_ctl_constructor(ctx, &ctl);
    HANDLE_EXCEPTION(cleanup_exit);

    file_transfer(src, dest, (controller*) &ctl);
    HANDLE_EXCEPTION(cleanup_ctl);

    cleanup_ctl:
    ftransform_extract_ctl_destructor(&ctl);
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
