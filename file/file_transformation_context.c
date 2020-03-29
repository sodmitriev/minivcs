#include "file_transformation_context.h"
#include <CEasyException/exception.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>

ftransform_ctx ftransform_ctx_extract(const struct config* conf)
{
    ftransform_ctx ret = {NULL, NULL, NULL, 0};
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

    ret.cipher = config_get("cipher", conf);
    if(ret.cipher)
    {
        if(ret.cipher[0] == '\0' || strcmp(ret.cipher, "none") == 0)
        {
            ret.cipher = NULL;
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

bool ftransform_ctx_is_encrypted(const ftransform_ctx* ctx)
{
    return ctx->cipher != NULL;
}

bool ftransform_ctx_is_compressed(const ftransform_ctx* ctx)
{
    return ctx->compression_level > 0;
}
