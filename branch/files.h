#ifndef MINIVCS_FILES_H
#define MINIVCS_FILES_H

#include <stddef.h>
#include <config/config.h>
#include <file/file_transformation_context.h>

struct file_index_value_by_hash;

struct file_index_value_by_name;

struct file_index
{
    const struct config* conf;
    const ftransform_ctx* ctx;
    const char* path;
    const char* file_dir;
    struct file_index_value_by_hash* by_hash;
    struct file_index_value_by_name* by_name;
    size_t name_size;
};

struct file_info;



extern void file_index_init(const struct config* conf, const ftransform_ctx* ctx, struct file_index* index);

extern void file_index_open(const struct config* conf, const ftransform_ctx* ctx, struct file_index* index);

extern void file_index_save(struct file_index* index);

extern void file_index_destroy(struct file_index* index);



extern struct file_info* file_index_find_by_hash(const unsigned char *hash, const struct file_index *index);

extern struct file_info* file_index_find_by_name(const unsigned char *name, const struct file_index *index);

extern struct file_info* file_index_insert(const unsigned char* hash, struct file_index* index);

extern size_t file_index_hash_size(const struct file_index* index);

extern const struct config* file_index_config(const struct file_index* index);

extern const char* file_index_file_dir(const struct file_index* index);

extern size_t file_index_name_size(struct file_index* index);



extern void file_info_add_ref(struct file_info* file); //ref++

extern void file_info_remove_ref(struct file_info* file); //ref--

extern const unsigned char *file_info_get_hash(struct file_info *file);

extern const unsigned char *file_info_get_name(struct file_info *file);

extern size_t file_info_get_ref(struct file_info *file);

#endif //MINIVCS_FILES_H
