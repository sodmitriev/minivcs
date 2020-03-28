#ifndef MINIVCS_OPERATIONS_H
#define MINIVCS_OPERATIONS_H

#include <config/config.h>
#include <CTransform/CEasyException/exception.h>

extern void file_hash(const char* path, const struct config* conf, unsigned char* hash);

extern size_t file_hash_size(const struct config* conf);

extern void file_store(const char* src, const char* dest, const char* key, const struct config* conf);

extern void file_extract(const char* src, const char* dest, const char* key, const struct config* conf);

extern void file_get_name(const unsigned char* raw, size_t raw_size, char* name);

extern size_t file_get_name_length(size_t raw_size);

#endif //MINIVCS_OPERATIONS_H
