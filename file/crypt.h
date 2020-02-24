#ifndef MINIVCS_CRYPT_H
#define MINIVCS_CRYPT_H

#include <stddef.h>

extern int encrypt_file(const char *src, const char* dest, const char* key, const char* cipher, const char* digest);

extern int decrypt_file(const char *src, const char* dest, const char* key, const char* cipher, const char* digest);

struct file_encrypted;

extern struct file_encrypted* file_encrypted_new();

extern void file_encrypted_delete(struct file_encrypted* file);

extern int
file_encrypted_open(const char *path, const char *mode, const char *key, const char *cipher, const char *digest,
                    struct file_encrypted *file);

extern int file_encrypted_close(struct file_encrypted* file);

extern int file_encrypted_read(char *ptr, size_t size, size_t* size_o, struct file_encrypted* file);

extern int file_encrypted_write(const char *ptr, size_t size, size_t* size_o, struct file_encrypted* file);

#endif //MINIVCS_CRYPT_H
