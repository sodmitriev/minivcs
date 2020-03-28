#ifndef MINIVCS_MINIVCS_H
#define MINIVCS_MINIVCS_H

#include <branch/branch.h>

struct minivcs_project
{
    struct config* conf;
    struct branch_index* index;
};

extern void minivcs_init_default(const char* metadata_path, struct minivcs_project* project);

extern void minivcs_init_from_config(const char* config_path, struct minivcs_project* project);

extern void minivcs_open(const char* config_path, struct minivcs_project* project);

extern void minivcs_destroy(struct minivcs_project* project);

extern void minivcs_new_branch(const char* branch_name, struct minivcs_project* project);

extern void minivcs_delete_branch(const char* branch_name, struct minivcs_project* project);

extern void minivcs_extract(const char* branch_name, const char* destination, struct minivcs_project* project);

extern void minivcs_update(const char* branch_name, const char* source, struct minivcs_project* project);

#endif //MINIVCS_MINIVCS_H
