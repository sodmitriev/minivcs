#ifndef MINIVCS_BRANCH_H
#define MINIVCS_BRANCH_H

#include "files.h"

struct branch_index_value;

struct branch_info_value;

struct branch_index
{
    FILE* file;
    const char* path;
    const char* branch_dir;
    struct branch_index_value* by_name;
    struct branch_index_value* by_file;
    size_t file_name_size;
    struct file_index files;
};

struct branch_info
{
    char* path;
    const char* branch_dir;
    char* imported_dir;
    FILE* file;
    struct branch_info_value* files_saved;
    struct branch_info_value* files;
    struct file_index* index;
};

extern int branch_index_init(const struct config* conf, struct branch_index* branch_index);

extern int branch_index_open(const struct config* conf, struct branch_index* branch_index);

extern int branch_index_save(struct branch_index* index);

extern int branch_index_destroy(struct branch_index* index);

extern int branch_index_new_branch(const char* name, struct branch_index* branch_index);

extern int branch_index_delete_branch(const char* name, struct branch_index* branch_index);

extern int branch_index_find(const char* name, struct branch_index* index, const char** file);

extern size_t branch_index_count(const struct branch_index* index);

extern void branch_index_get_names(const char** names, const struct branch_index* index);



extern int branch_index_get_branch(const char* name, struct branch_index* index, struct branch_info* branch);

extern int branch_save(struct branch_info* branch);

extern int branch_destroy(struct branch_info* branch);

extern int branch_extract(const struct branch_info* branch, const char* dst_dir);

extern int branch_update(struct branch_info* branch, const char* src_dir);

#endif //MINIVCS_BRANCH_H
