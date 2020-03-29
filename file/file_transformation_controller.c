#include "file_transformation_controller.h"

#define HANDLE_EXCEPTION(lable) if(EXCEPTION_IS_THROWN) goto lable; ((void)(0))

void ftransform_store_ctl_constructor(const ftransform_ctx* ctx, ftransform_store_ctl *this)
{

    controller_constructor(&this->ctl);
    HANDLE_EXCEPTION(cleanup_exit);

    if(ftransform_ctx_is_compressed(ctx))
    {
        transformation_compress_constructor((int) ctx->compression_level, &this->compress);
        HANDLE_EXCEPTION(cleanup_ctl);

        controller_add_transformation((transformation*) &this->compress, &this->ctl);
        HANDLE_EXCEPTION(cleanup_compress);
    }

    if(ftransform_ctx_is_encrypted(ctx))
    {
        assert(ctx->password);
        transformation_encrypt_constructor(ctx->cipher, ctx->key_digest, ctx->password, &this->encrypt);
        HANDLE_EXCEPTION(cleanup_compress);

        controller_add_transformation((transformation*) &this->encrypt, &this->ctl);
        HANDLE_EXCEPTION(cleanup_encrypt);
    }

    this->ctx = ctx;
    return;

    cleanup_encrypt:
    if(ftransform_ctx_is_encrypted(ctx))
        transformation_destructor((transformation*) &this->encrypt);
    cleanup_compress:
    if(ftransform_ctx_is_compressed(ctx))
        transformation_destructor((transformation*) &this->compress);
    cleanup_ctl:
    controller_destructor(&this->ctl);
    cleanup_exit:
    ((void)(0));
}

void ftransform_store_ctl_destructor(ftransform_store_ctl *this)
{
    if(ftransform_ctx_is_encrypted(this->ctx))
        transformation_destructor((transformation*) &this->encrypt);
    if(ftransform_ctx_is_compressed(this->ctx))
        transformation_destructor((transformation*) &this->compress);
    controller_destructor(&this->ctl);
}

void ftransform_extract_ctl_constructor(const ftransform_ctx* ctx, ftransform_extract_ctl *this)
{
    controller_constructor(&this->ctl);
    HANDLE_EXCEPTION(cleanup_exit);

    if(ftransform_ctx_is_encrypted(ctx))
    {
        assert(ctx->password);
        transformation_decrypt_constructor(ctx->cipher, ctx->key_digest, ctx->password, &this->decrypt);
        HANDLE_EXCEPTION(cleanup_ctl);

        controller_add_transformation((transformation*) &this->decrypt, &this->ctl);
        HANDLE_EXCEPTION(cleanup_decrypt);
    }

    if(ftransform_ctx_is_compressed(ctx))
    {
        transformation_decompress_constructor(&this->decompress);
        HANDLE_EXCEPTION(cleanup_decrypt);

        controller_add_transformation((transformation*) &this->decompress, &this->ctl);
        HANDLE_EXCEPTION(cleanup_decompress);
    }

    this->ctx = ctx;
    return;

    cleanup_decompress:
    if(ftransform_ctx_is_compressed(ctx))
        transformation_destructor((transformation*) &this->decompress);
    cleanup_decrypt:
    if(ftransform_ctx_is_encrypted(ctx))
        transformation_destructor((transformation*) &this->decrypt);
    cleanup_ctl:
    controller_destructor(&this->ctl);
    cleanup_exit:
    ((void)(0));
}

void ftransform_extract_ctl_destructor(ftransform_extract_ctl *this)
{
    if(ftransform_ctx_is_compressed(this->ctx))
        transformation_destructor((transformation*) &this->decompress);
    if(ftransform_ctx_is_encrypted(this->ctx))
        transformation_destructor((transformation*) &this->decrypt);
    controller_destructor(&this->ctl);
}
