#ifndef MINIVCS_MINIVCS_H
#define MINIVCS_MINIVCS_H

#include <branch/branch.h>

struct minivcs_project
{
    struct config conf;
    struct branch_index index;
    bool index_loaded;
    ftransform_ctx ctx;
};

extern void minivcs_generate_config(const char* metadata_path);

extern void minivcs_read_config(const char* config_path, struct minivcs_project* project);

extern bool minivcs_need_password(struct minivcs_project* project);

extern void minivcs_set_password(const char* password, struct minivcs_project* project);

extern void minivcs_init_from_config(struct minivcs_project* project);

extern void minivcs_open_from_config(struct minivcs_project* project);

extern void minivcs_destroy(struct minivcs_project* project);

extern void minivcs_new_branch(const char* branch_name, struct minivcs_project* project);

extern void minivcs_delete_branch(const char* branch_name, struct minivcs_project* project);

extern void minivcs_extract(const char* branch_name, const char* destination, struct minivcs_project* project);

extern void minivcs_update(const char* branch_name, const char* source, struct minivcs_project* project);

#endif //MINIVCS_MINIVCS_H
