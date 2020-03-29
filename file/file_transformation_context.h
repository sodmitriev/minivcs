#ifndef MINIVCS_FILE_TRANSFORMATION_CONTEXT_H
#define MINIVCS_FILE_TRANSFORMATION_CONTEXT_H

#include "config/config.h"
#include <stdbool.h>

typedef struct
{
    const char* key_digest;
    const char* cipher;
    const char* password;
    int compression_level;
} ftransform_ctx;

ftransform_ctx ftransform_ctx_extract(const struct config* conf);
bool ftransform_ctx_is_encrypted(const ftransform_ctx* ctx);
bool ftransform_ctx_is_compressed(const ftransform_ctx* ctx);

#endif //MINIVCS_FILE_TRANSFORMATION_CONTEXT_H
