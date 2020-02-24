#include "crypt.h"
#include <ec.h>
#include <openssl/evp.h>
#include <assert.h>
#include <string.h>

int encrypt_file(const char *src, const char* dest, const char* key, const char* cipher, const char* digest)
{
    FILE* in = fopen(src, "r");
    if(!in)
    {
        return ERROR_SYSTEM;
    }
    struct file_encrypted* out = file_encrypted_new();
    if(!out)
    {
        fclose(in);
        return ERROR_SYSTEM;
    }

    int err;
    if((err = file_encrypted_open(dest, "w", key, cipher, digest, out)) != ERROR_SUCCESS)
    {
        fclose(in);
        file_encrypted_delete(out);
        return err;
    }

    char buf[512];
    size_t num;
    while((num = fread(buf, 1, sizeof(buf), in)) > 0)
    {
        err = file_encrypted_write(buf, num, NULL, out);
        if(err != ERROR_SUCCESS)
        {
            fclose(in);
            file_encrypted_close(out);
            file_encrypted_delete(out);
            return err;
        }
    }
    if(ferror(in))
    {
        fclose(in);
        file_encrypted_close(out);
        file_encrypted_delete(out);
        return ERROR_SYSTEM;
    }
    fclose(in);
    file_encrypted_close(out);
    file_encrypted_delete(out);
    return ERROR_SUCCESS;
}

int decrypt_file(const char *src, const char* dest, const char* key, const char* cipher, const char* digest)
{
    FILE* out = fopen(dest, "w");
    if(!out)
    {
        return ERROR_SYSTEM;
    }
    struct file_encrypted* in = file_encrypted_new();
    if(!in)
    {
        fclose(out);
        return ERROR_SYSTEM;
    }

    int err;
    if((err = file_encrypted_open(src, "r", key, cipher, digest, in)) != ERROR_SUCCESS)
    {
        fclose(out);
        file_encrypted_delete(in);
        return err;
    }

    char buf[512];
    size_t num;

    while(err = file_encrypted_read(buf, sizeof(buf), &num, in), num > 0 && err == ERROR_SUCCESS)
    {
        size_t wrnum = fwrite(buf, 1, num, out);
        if(wrnum != num)
        {
            fclose(out);
            file_encrypted_close(in);
            file_encrypted_delete(in);
            return ERROR_SYSTEM;
        }
    }
    if(err != ERROR_SUCCESS)
    {
        fclose(out);
        file_encrypted_close(in);
        file_encrypted_delete(in);
        return err;
    }
    fclose(out);
    file_encrypted_close(in);
    file_encrypted_delete(in);
    return ERROR_SUCCESS;
}

struct file_encrypted
{
    FILE* file;
    EVP_CIPHER_CTX* ctx;
    char* pending;
    size_t block_size;
    size_t size;
    size_t pos;
    int finished;
    int encrypt;
};

struct file_encrypted* file_encrypted_new()
{
    return malloc(sizeof(struct file_encrypted));
}

void file_encrypted_delete(struct file_encrypted* file)
{
    free(file);
}

int
file_encrypted_open(const char *path, const char *mode, const char *key, const char *cipher, const char *digest,
                    struct file_encrypted *file)
{
    assert(file);

    const EVP_CIPHER* ciph = EVP_get_cipherbyname(cipher);
    const EVP_MD* md = EVP_get_digestbyname(digest);

    if(ciph == NULL || md == NULL)
    {
        return ERROR_NOTFOUND;
    }

    const int key_size = EVP_CIPHER_key_length(ciph);
    const int iv_size = EVP_CIPHER_iv_length(ciph);
    const size_t key_len = strlen(key);

    unsigned char* raw_key = malloc(key_size);
    if(raw_key == NULL)
    {
        return ERROR_SYSTEM;
    }
    unsigned char* iv = malloc(iv_size);
    if(iv == NULL)
    {
        free(raw_key);
        return ERROR_SYSTEM;
    }
    memset(iv, 0, iv_size);

    file->block_size = EVP_CIPHER_block_size(ciph);
    file->pending = malloc(file->block_size * 2); //Block for input + block for output are required by openssl
    if(!file->pending)
    {
        free(raw_key);
        free(iv);
        return ERROR_SYSTEM;
    }

    file->pos = file->block_size * 2;
    file->size = 0;
    file->finished = 0;

    file->ctx = EVP_CIPHER_CTX_new();
    if (file->ctx == NULL)
    {
        free(raw_key);
        free(iv);
        free(file->pending);
        return ERROR_SYSTEM;
    }

    unsigned char salt[] = {37, 82, 152, 215, 173, 161, 143, 54};
    if (EVP_BytesToKey(ciph, md, salt, key, key_len, 3, raw_key, iv) != key_size)
    {
        free(raw_key);
        free(iv);
        free(file->pending);
        EVP_CIPHER_CTX_free(file->ctx);
        return ERROR_CRYPTO;
    }

    int ret;
    if (strcmp(mode, "w") == 0)
    {
        ret = EVP_EncryptInit_ex(file->ctx, ciph, NULL, raw_key, iv);
        file->encrypt = 1;
    }
    else if(strcmp(mode, "r") == 0)
    {
        ret = EVP_DecryptInit_ex(file->ctx, ciph, NULL, raw_key, iv);
        file->encrypt = 0;
    }
    else
    {
        free(raw_key);
        free(iv);
        free(file->pending);
        EVP_CIPHER_CTX_free(file->ctx);
        return ERROR_MODE;
    }

    free(raw_key);
    free(iv);

    if(ret == 0)
    {
        free(file->pending);
        EVP_CIPHER_CTX_free(file->ctx);
        return ERROR_CRYPTO;
    }

    file->file = fopen(path, mode);
    if(!file->file)
    {
        free(file->pending);
        EVP_CIPHER_CTX_free(file->ctx);
        return ERROR_SYSTEM;
    }
    return ERROR_SUCCESS;
}

int file_encrypted_close(struct file_encrypted* file)
{
    if(file->encrypt)
    {
        int len;
        if ( EVP_EncryptFinal_ex(file->ctx, file->pending, &len) != 1 )
        {
            return ERROR_CRYPTO;
        }
        if(fwrite(file->pending, 1, len, file->file) != len)
        {
            return ERROR_SYSTEM;
        }
        file->size = len;
    }
    EVP_CIPHER_CTX_free(file->ctx);
    fclose(file->file);
    free(file->pending);
    return ERROR_SUCCESS;
}

int file_encrypted_read(char *ptr, size_t size, size_t* size_o, struct file_encrypted* file)
{
    if(size_o)
    {
        *size_o = 0;
    }
    if(file->pos < file->size)
    {
        size_t left = file->size - file->pos;
        if(left >= size)
        {
            memcpy(ptr, file->pending + file->pos, size);
            file->pos += size;
            if(size_o)
            {
                *size_o = size;
            }
            return ERROR_SUCCESS;
        }
        else
        {
            memcpy(ptr, file->pending + file->pos, left);
            ptr += left;
            size -= left;
            if(size_o)
            {
                *size_o = left;
            }
        }
    }
    int len = 0;
    char* buf = malloc(file->block_size);
    if(!buf)
    {
        return ERROR_SYSTEM;
    }
    while(!feof(file->file) && size > 0)
    {
        size_t n = fread(buf, 1, file->block_size, file->file);
        if(ferror(file->file))
        {
            free(buf);
            return ERROR_SYSTEM;
        }
        if ( EVP_DecryptUpdate(file->ctx, file->pending, &len, buf, n) != 1)
        {
            free(buf);
            return ERROR_CRYPTO;
        }
        file->size = len;
        size_t num = file->size > size ? size : file->size;
        memcpy(ptr, file->pending , num);
        file->pos = num;
        ptr += num;
        size -= num;
        if(size_o)
        {
            *size_o += num;
        }
    }
    len = 0;
    if(feof(file->file) && size > 0 && !file->finished)
    {
        if (( EVP_DecryptFinal_ex(file->ctx, file->pending, &len)) != 1)
        {
            free(buf);
            return ERROR_CRYPTO;
        }
        file->size = len;
        size_t num = file->size > size ? size : file->size;
        memcpy(ptr, file->pending, num);
        file->pos = num;
        if(size_o)
        {
            *size_o += num;
        }
        file->finished = 1;
    }
    free(buf);
    return ERROR_SUCCESS;
}

int file_encrypted_write(const char *ptr, size_t size, size_t* size_o, struct file_encrypted* file)
{
    if(size_o)
    {
        *size_o = 0;
    }
    int len = 0;
    while(size > 0)
    {
        int num = file->block_size < size ? file->block_size : size;
        if ( EVP_EncryptUpdate(file->ctx, file->pending, &len, ptr, num ) != 1)
        {
            return ERROR_CRYPTO;
        }
        if(fwrite(file->pending, 1, len, file->file) != len)
        {
            return ERROR_SYSTEM;
        }
        file->size = len;
        ptr += num;
        size -= num;
        if(size_o)
        {
            *size_o += num;
        }
    }
    return ERROR_SUCCESS;
}
