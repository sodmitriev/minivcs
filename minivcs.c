#include "minivcs.h"
#include <config/config.h>
#include <branch/branch.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <zconf.h>
#include <string.h>

struct branch_info_list
{
    struct branch_info* branch;
    struct branch_info_list* next;
};

#define INIT_DEFAULT_MKDIR(dir)                                         \
strcpy(path_end, dir);                                                  \
if(mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO) < 0 && errno != EEXIST)     \
{                                                                       \
    err = ERROR_SYSTEM;                                                 \
    goto minivcs_init_default_fail;                                     \
}                                                                       \
((void)(0))

#define INIT_DEFAULT_CONFIG_SET(key, value)                             \
err = config_set(key, value, project->conf);                            \
if(err != ERROR_SUCCESS)                                                \
{                                                                       \
    goto minivcs_init_default_fail_config;                              \
}                                                                       \
((void)(0))

static int create_subdirs(char* path)
{
    while(*path == '/')
    {
        ++path;
    }
    for(char* pos = strchr(path, '/'); pos != NULL; pos = strchr(pos + 1, '/'))
    {
        *pos = '\0';
        struct stat file_stat;
        int err = stat(path, &file_stat);
        if(err == 0 && !S_ISDIR(file_stat.st_mode))
        {
            *pos = '/';
            return ERROR_FILETYPE;
        }
        else if(err < 0 && errno == ENOENT)
        {
            err = mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO);
            *pos = '/';
            if(err < 0)
            {
                return ERROR_SYSTEM;
            }
        }
        else if(err < 0)
        {
            *pos = '/';
            return ERROR_SYSTEM;
        }
        else
        {
            *pos = '/';
        }
    }
    return ERROR_SUCCESS;
}

int minivcs_init_default(const char* metadata_path, struct minivcs_project* project)
{
    int err = ERROR_SUCCESS;
    project->conf = malloc(sizeof(struct config));
    project->index = malloc(sizeof(struct branch_index));
    char* path = malloc(PATH_MAX + 1);
    if(!project->conf || !project->index || !path)
    {
        err = ERROR_SYSTEM;
        goto minivcs_init_default_fail;
    }
    strcpy(path, metadata_path);
    char* path_end = strchr(path, '\0');
    *path_end = '/';
    ++path_end;
    INIT_DEFAULT_MKDIR("branches");
    INIT_DEFAULT_MKDIR("files");
    strcpy(path_end, "config");
    err = config_init(path, project->conf);
    if(err != ERROR_SUCCESS)
    {
        goto minivcs_init_default_fail;
    }
    strcpy(path_end, "branches/index");
    INIT_DEFAULT_CONFIG_SET("branch_index_path", path);
    strcpy(path_end, "branches");
    INIT_DEFAULT_CONFIG_SET("branch_dir", path);
    INIT_DEFAULT_CONFIG_SET("branch_digest", "sha1");
    INIT_DEFAULT_CONFIG_SET("branch_name_len", "32");
    strcpy(path_end, "files/index");
    INIT_DEFAULT_CONFIG_SET("file_index_path", path);
    strcpy(path_end, "files");
    INIT_DEFAULT_CONFIG_SET("file_dir", path);
    INIT_DEFAULT_CONFIG_SET("file_digest", "sha1");
    INIT_DEFAULT_CONFIG_SET("file_name_len", "32");
    err = branch_index_init(project->conf, project->index);
    if(err != ERROR_SUCCESS)
    {
        goto minivcs_init_default_fail_config;
    }
    err = branch_index_save(project->index);
    if(err != ERROR_SUCCESS)
    {
        goto minivcs_init_default_fail_config;
    }
    err = config_save(project->conf);
    if(err != ERROR_SUCCESS)
    {
        goto minivcs_init_default_fail_config;
    }
    free(path);
    return ERROR_SUCCESS;

minivcs_init_default_fail_config:
    config_destroy(project->conf);
minivcs_init_default_fail:
    free(path);
    free(project->conf);
    free(project->index);
    return err;
}

int minivcs_init_from_config(const char* config_path, struct minivcs_project* project)
{
    int err = ERROR_SUCCESS;
    char* branch_dir = NULL;
    char* file_dir = NULL;
    project->conf = malloc(sizeof(struct config));
    project->index = malloc(sizeof(struct branch_index));
    char* path = malloc(PATH_MAX + 1);
    if(!project->conf || !project->index || !path)
    {
        err = ERROR_SYSTEM;
        goto minivcs_init_from_config_fail;
    }
    err = config_load(config_path, project->conf);
    if(err != ERROR_SUCCESS)
    {
        goto minivcs_init_from_config_fail;
    }
    const char* cbranch_dir = config_get("branch_dir", project->conf);
    const char* cfile_dir = config_get("file_dir", project->conf);
    if(!cbranch_dir || !cfile_dir)
    {
        err = ERROR_CONFIG;
        goto minivcs_init_from_config_fail;
    }
    branch_dir = malloc(strlen(cbranch_dir)+ 2);
    file_dir = malloc(strlen(cfile_dir)+ 2);
    if(!branch_dir || !file_dir)
    {
        err = ERROR_SYSTEM;
        goto minivcs_init_from_config_fail;
    }
    strcpy(branch_dir, cbranch_dir);
    strcat(branch_dir, "/");
    strcpy(file_dir, cfile_dir);
    strcat(file_dir, "/");
    err = create_subdirs(branch_dir);
    if(err != ERROR_SUCCESS)
    {
        goto minivcs_init_from_config_fail_config;
    }
    err = create_subdirs(file_dir);
    if(err != ERROR_SUCCESS)
    {
        goto minivcs_init_from_config_fail_config;
    }
    err = branch_index_init(project->conf, project->index);
    if(err != ERROR_SUCCESS)
    {
        goto minivcs_init_from_config_fail_config;
    }
    free(path);
    free(branch_dir);
    free(file_dir);
    return ERROR_SUCCESS;

minivcs_init_from_config_fail_config:
    config_destroy(project->conf);
minivcs_init_from_config_fail:
    free(project->conf);
    free(project->index);
    free(branch_dir);
    free(file_dir);
    return err;
}

int minivcs_open(const char* config_path, struct minivcs_project* project)
{
    int err = ERROR_SUCCESS;
    project->conf = malloc(sizeof(struct config));
    project->index = malloc(sizeof(struct branch_index));
    char* path = malloc(PATH_MAX + 1);
    if(!project->conf || !project->index || !path)
    {
        err = ERROR_SYSTEM;
        goto minivcs_init_from_config_fail;
    }
    err = config_load(config_path, project->conf);
    if(err != ERROR_SUCCESS)
    {
        goto minivcs_init_from_config_fail;
    }
    err = branch_index_open(project->conf, project->index);
    if(err != ERROR_SUCCESS)
    {
        goto minivcs_init_from_config_fail_config;
    }
    free(path);
    return ERROR_SUCCESS;

    minivcs_init_from_config_fail_config:
    config_destroy(project->conf);
    minivcs_init_from_config_fail:
    free(project->conf);
    free(project->index);
    free(path);
    return err;
}

int minivcs_destroy(struct minivcs_project* project)
{
    int err1 = branch_index_destroy(project->index);
    int err2 = config_destroy(project->conf);
    free(project->index);
    free(project->conf);
    if(err1 != ERROR_SUCCESS)
    {
        return err1;
    }
    return err2;
}

int minivcs_new_branch(const char* branch_name, struct minivcs_project* project)
{
    int err = branch_index_new_branch(branch_name, project->index);
    if(err == ERROR_SUCCESS)
    {
        err = branch_index_save(project->index);
    }
    return err;
}

int minivcs_delete_branch(const char* branch_name, struct minivcs_project* project)
{
    int err = branch_index_delete_branch(branch_name, project->index);
    if(err == ERROR_SUCCESS)
    {
        err = branch_index_save(project->index);
    }
    return err;
}

int minivcs_extract(const char* branch_name, const char* destination, struct minivcs_project* project)
{
    int err = ERROR_SUCCESS;
    struct branch_info branch;
    err = branch_index_get_branch(branch_name, project->index, &branch);
    if(err != ERROR_SUCCESS)
    {
        return err;
    }
    err = branch_extract(&branch, destination);
    if(err != ERROR_SUCCESS)
    {
        int tmp = errno;
        branch_destroy(&branch);
        errno = tmp;
        return err;
    }
    return branch_destroy(&branch);
}

int minivcs_update(const char* branch_name, const char* source, struct minivcs_project* project)
{
    int err = ERROR_SUCCESS;
    struct branch_info branch;
    err = branch_index_get_branch(branch_name, project->index, &branch);
    if(err != ERROR_SUCCESS)
    {
        return err;
    }
    err = branch_update(&branch, source);
    if(err != ERROR_SUCCESS)
    {
        int tmp = errno;
        branch_destroy(&branch);
        errno = tmp;
        return err;
    }
    err = branch_save(&branch);
    if(err != ERROR_SUCCESS)
    {
        int tmp = errno;
        branch_destroy(&branch);
        errno = tmp;
        return err;
    }
    return branch_destroy(&branch);
}
