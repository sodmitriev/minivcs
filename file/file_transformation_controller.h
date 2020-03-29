#ifndef MINIVCS_FILE_TRANSFORMATION_CONTROLLER_H
#define MINIVCS_FILE_TRANSFORMATION_CONTROLLER_H

#include "file_transformation_context.h"

#include <CTransform/controller.h>
#include <CTransform/crypto/transformation_encrypt.h>
#include <CTransform/crypto/transformation_decrypt.h>
#include <CTransform/compress/transformation_compress.h>
#include <CTransform/compress/transformation_decompress.h>

typedef struct
{
    controller ctl;
    transformation_compress compress;
    transformation_encrypt encrypt;
    const ftransform_ctx* ctx;
} ftransform_store_ctl;


typedef struct
{
    controller ctl;
    transformation_decrypt decrypt;
    transformation_decompress decompress;
    const ftransform_ctx* ctx;
} ftransform_extract_ctl;


void ftransform_store_ctl_constructor(const ftransform_ctx* ctx, ftransform_store_ctl *this);

void ftransform_store_ctl_destructor(ftransform_store_ctl *this);


void ftransform_extract_ctl_constructor(const ftransform_ctx* ctx, ftransform_extract_ctl *this);

void ftransform_extract_ctl_destructor(ftransform_extract_ctl *this);

#endif //MINIVCS_FILE_TRANSFORMATION_CONTROLLER_H
