#include "crypto_stream.h"
#include "layered_stream_def.h"
#include <stdlib.h>
#include <openssl/evp.h>
#include <errno.h>
#include <string.h>

struct layered_stream_crypto
{
    struct layered_stream base;
    EVP_CIPHER_CTX* ctx;
    char* pending;
    char* buf;
    size_t buf_size;
    size_t block_size;
    size_t size;
    size_t pos;
    int finished;
    int encrypt;
    int failed;
};

size_t layered_stream_crypto_read(char* ptr, size_t size, struct layered_stream_crypto* stream)
{
    if(stream->encrypt)
    {
        errno = EPERM;
        return 0;
    }
    ssize_t ret = 0;
    if(stream->pos < stream->size)
    {
        size_t left = stream->size - stream->pos;
        if(left >= size)
        {
            memcpy(ptr, stream->pending + stream->pos, size);
            stream->pos += size;
            ret = size;
            return ret;
        }
        else
        {
            memcpy(ptr, stream->pending + stream->pos, left);
            ptr += left;
            size -= left;
            ret = left;
            stream->pos += left;
        }
    }
    int len = 0;
    while(!layered_stream_eof(stream->base.source) && size > 0)
    {
        if (stream->buf_size == 0)
        {
            stream->buf_size = layered_stream_read(stream->buf, stream->block_size, stream->base.source);
            if (layered_stream_error(stream->base.source))
            {
                stream->failed = 1;
                return ret;
            }
        }
        if ( EVP_DecryptUpdate(stream->ctx, stream->pending, &len, stream->buf, stream->buf_size) != 1)
        {
            stream->failed = 1;
            errno = ENOANO;
            return ret;
        }
        stream->buf_size = 0;
        stream->size = len;
        size_t num = stream->size > size ? size : stream->size;
        memcpy(ptr, stream->pending , num);
        stream->pos = num;
        ptr += num;
        size -= num;
        ret += num;
    }
    len = 0;
    if(layered_stream_eof(stream->base.source) && size > 0 && !stream->finished)
    {
        if (( EVP_DecryptFinal_ex(stream->ctx, stream->pending, &len)) != 1)
        {
            stream->failed = 1;
            errno = ENOANO;
            return ret;
        }
        stream->size = len;
        size_t num = stream->size > size ? size : stream->size;
        memcpy(ptr, stream->pending, num);
        stream->pos = num;
        ret += num;
        stream->finished = 1;
    }
    return ret;
}

size_t layered_stream_crypto_write(const char* ptr, size_t size, struct layered_stream_crypto* stream)
{
    if(!stream->encrypt)
    {
        errno = EPERM;
        return 0;
    }
    ssize_t ret = 0;
    int len = 0;
    while(size > 0)
    {
        size_t num = stream->block_size < size ? stream->block_size : size;
        if ( EVP_EncryptUpdate(stream->ctx, stream->pending, &len, ptr, num ) != 1)
        {
            errno = ENOANO;
            stream->failed = 1;
            return 0;
        }
        if(layered_stream_write(stream->pending, len, stream->base.source) != len)
        {
            stream->failed = 1;
            return 0;
        }
        stream->size = len;
        ptr += num;
        size -= num;
        ret += num;
    }
    return ret;
}

int layered_stream_crypto_eof(struct layered_stream_crypto* stream)
{
    return !stream->encrypt && stream->finished;
}

int layered_stream_crypto_error(struct layered_stream_crypto* stream)
{
    return stream->failed;
}

void layered_stream_crypto_clearerr(struct layered_stream_crypto* stream)
{
    stream->failed = 0;
    layered_stream_clearerr(stream->base.source);
}

static int layered_stream_crypto_finalize(struct layered_stream_crypto* stream)
{
    if(!stream->finished && stream->encrypt)
    {
        int len;
        if ( EVP_EncryptFinal_ex(stream->ctx, stream->pending, &len) != 1 )
        {
            errno = ENOANO;
            stream->failed = -1;
            return -1;
        }
        if(layered_stream_write(stream->pending, len, stream->base.source) != len)
        {
            stream->failed = -1;
            return -1;
        }
        stream->finished = 1;
    }
    return 0;
}

int layered_stream_crypto_close(struct layered_stream_crypto* stream)
{
    int err = layered_stream_crypto_finalize(stream);
    if(layered_stream_close(stream->base.source) < 0)
    {
        err = -1;
    }
    EVP_CIPHER_CTX_free(stream->ctx);
    free(stream->pending);
    free(stream->buf);
    free(stream);
    return err;
}

const struct layered_stream_call_tab layered_stream_call_tab_crypto =
{
    .read_func      = (size_t (*)(char *, size_t, struct layered_stream *))         layered_stream_crypto_read,
    .write_func     = (size_t (*)(const char *, size_t, struct layered_stream *))   layered_stream_crypto_write,
    .eof_func       = (int (*)(struct layered_stream *))                            layered_stream_crypto_eof,
    .error_func     = (int (*)(struct layered_stream *))                            layered_stream_crypto_error,
    .clearerr_func  = (void (*)(struct layered_stream *))                           layered_stream_crypto_clearerr,
    .close_func     = (int (*)(struct layered_stream *))                            layered_stream_crypto_close
};

struct layered_stream_crypto* layered_stream_crypto_open(lrdstream* source, const char* cipher, const char* digest, const char* key, int encrypt)
{
    const EVP_CIPHER* ciph = EVP_get_cipherbyname(cipher);
    const EVP_MD* md = EVP_get_digestbyname(digest);

    if(ciph == NULL || md == NULL)
    {
        errno = EINVAL;
        return NULL;
    }

    const int key_size = EVP_CIPHER_key_length(ciph);
    const int iv_size = EVP_CIPHER_iv_length(ciph);
    const size_t block_size = EVP_CIPHER_block_size(ciph);
    const size_t key_len = strlen(key);

    struct layered_stream_crypto* stream = malloc(sizeof(struct layered_stream_crypto));
    unsigned char* raw_key = malloc(key_size);
    unsigned char* iv = malloc(iv_size);
    char* pending = malloc(block_size * 2); //Block for input + block for output are required by openssl
    char* buf = malloc(block_size * 2);
    if(!stream || !raw_key || !iv || !pending || !buf)
    {
        goto layered_stream_crypto_open_cleanup;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
    {
        goto layered_stream_crypto_open_cleanup;
    }

    unsigned char salt[] = {37, 82, 152, 215, 173, 161, 143, 54};
    if (EVP_BytesToKey(ciph, md, salt, key, key_len, 3, raw_key, iv) != key_size)
    {
        errno = ENOANO;
        goto layered_stream_crypto_open_cleanup_ctx;
    }

    int ret;
    if (encrypt)
    {
        ret = EVP_EncryptInit_ex(ctx, ciph, NULL, raw_key, iv);
    }
    else
    {
        ret = EVP_DecryptInit_ex(ctx, ciph, NULL, raw_key, iv);
    }

    if(!ret)
    {
        errno = ENOANO;
        goto layered_stream_crypto_open_cleanup_ctx;
    }

    memset(iv, 0, iv_size);

    stream->block_size = EVP_CIPHER_block_size(ciph);
    stream->pending = pending;
    stream->buf = buf;
    stream->pos = block_size * 2;
    stream->size = 0;
    stream->finished = 0;
    stream->ctx = ctx;
    stream->encrypt = encrypt;
    stream->failed = 0;
    stream->buf_size = 0;

    stream->base.source = source;
    stream->base.calls = &layered_stream_call_tab_crypto;
    free(raw_key);
    free(iv);
    return stream;

layered_stream_crypto_open_cleanup_ctx:
    EVP_CIPHER_CTX_free(ctx);
layered_stream_crypto_open_cleanup:
    free(stream);
    free(raw_key);
    free(iv);
    free(pending);
    free(buf);
    return NULL;
}
