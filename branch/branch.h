#ifndef MINIVCS_BRANCH_H
#define MINIVCS_BRANCH_H

#include "files.h"

struct branch_index
{

};

struct branch_info
{

};

extern int init_branch_index(const struct config* conf, struct branch_index* branch_index);

extern int open_branch_index(const struct config* conf, struct branch_index* branch_index);

extern int close_branch_index(struct branch_index* index);



extern int new_branch(struct branch_index* index, const char* name, struct branch_info* ret);

extern int open_branch(const struct branch_index* index, const char* name, struct branch_info* ret);

extern int close_branch(struct branch_info* ret);

extern int extract_branch(const struct branch_info* branch, const char* dst);

extern int update_branch(const struct branch_info* branch, const char* src);

extern int copy_branch(struct branch_info* src, struct branch_info* dst);



extern int add_file_to_branch(struct branch_info* branch, struct file_info* file);

extern int rm_file_from_branch(struct branch_info* branch, struct file_info* file);

#endif //MINIVCS_BRANCH_H
