#include "minivcs.h"
#include <config/config.h>
#include <branch/branch.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <zconf.h>
#include <string.h>
#include <CEasyException/exception.h>

struct branch_info_list
{
    struct branch_info* branch;
    struct branch_info_list* next;
};

#define INIT_DEFAULT_MKDIR(dir)                                         \
strcpy(path_end, dir);                                                  \
if(mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO) < 0 && errno != EEXIST)     \
{                                                                       \
    EXCEPTION_THROW(errno, "Failed to create directory \"%s\"", path);  \
    goto minivcs_init_default_fail;                                     \
}                                                                       \
((void)(0))

#define INIT_DEFAULT_CONFIG_SET(key, value)                             \
config_set(key, value, project->conf);                                  \
if(EXCEPTION_IS_THROWN)                                                 \
{                                                                       \
    goto minivcs_init_default_fail_config;                              \
}                                                                       \
((void)(0))

static void create_subdirs(char* path)
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
            EXCEPTION_THROW(ENOTDIR, "Failed to create subdirectory \"%s\", file with the same path exists", path);
            *pos = '/';
            return;
        }
        else if(err < 0 && errno == ENOENT)
        {
            err = mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO);
            if(err < 0)
            {
                EXCEPTION_THROW(errno, "Failed to create subdirectory \"%s\"", path);
                *pos = '/';
                return;
            }
            *pos = '/';
        }
        else if(err < 0)
        {
            *pos = '/';
            EXCEPTION_THROW(errno, "Failed to stat file \"%s\"", path);
            return;
        }
        else
        {
            *pos = '/';
        }
    }
}

void minivcs_init_default(const char* metadata_path, struct minivcs_project* project)
{
    project->conf = malloc(sizeof(struct config));
    project->index = malloc(sizeof(struct branch_index));
    char* path = malloc(PATH_MAX + 1);
    if(!project->conf || !project->index || !path)
    {
        EXCEPTION_THROW_NOMSG(errno);
        goto minivcs_init_default_fail;
    }
    strcpy(path, metadata_path);
    char* path_end = strchr(path, '\0');
    *path_end = '/';
    ++path_end;
    INIT_DEFAULT_MKDIR("branches");
    INIT_DEFAULT_MKDIR("files");
    strcpy(path_end, "config");
    config_init(path, project->conf);
    if(EXCEPTION_IS_THROWN)
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
    branch_index_init(project->conf, project->index);
    if(EXCEPTION_IS_THROWN)
    {
        goto minivcs_init_default_fail_config;
    }
    branch_index_save(project->index);
    if(EXCEPTION_IS_THROWN)
    {
        goto minivcs_init_default_fail_config;
    }
    config_save(project->conf);
    if(EXCEPTION_IS_THROWN)
    {
        goto minivcs_init_default_fail_config;
    }
    free(path);
    return;

minivcs_init_default_fail_config:
    config_destroy(project->conf);
minivcs_init_default_fail:
    free(path);
    free(project->conf);
    free(project->index);
}

void minivcs_init_from_config(const char* config_path, struct minivcs_project* project)
{
    char* branch_dir = NULL;
    char* file_dir = NULL;
    project->conf = malloc(sizeof(struct config));
    project->index = malloc(sizeof(struct branch_index));
    char* path = malloc(PATH_MAX + 1);
    if(!project->conf || !project->index || !path)
    {
        EXCEPTION_THROW_NOMSG(errno);
        goto minivcs_init_from_config_fail;
    }
    config_load(config_path, project->conf);
    if(EXCEPTION_IS_THROWN)
    {
        goto minivcs_init_from_config_fail;
    }
    const char* cbranch_dir = config_get("branch_dir", project->conf);
    const char* cfile_dir = config_get("file_dir", project->conf);
    if(!cbranch_dir)
    {
        EXCEPTION_THROW(EINVAL, "%s", "\"branch_dir\" is not found in config");
        goto minivcs_init_from_config_fail;
    }
    if(!cfile_dir)
    {
        EXCEPTION_THROW(EINVAL, "%s", "\"file_dir\" is not found in config");
        goto minivcs_init_from_config_fail;
    }

    branch_dir = malloc(strlen(cbranch_dir)+ 2);
    file_dir = malloc(strlen(cfile_dir)+ 2);
    if(!branch_dir || !file_dir)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        goto minivcs_init_from_config_fail;
    }
    strcpy(branch_dir, cbranch_dir);
    strcat(branch_dir, "/");
    strcpy(file_dir, cfile_dir);
    strcat(file_dir, "/");
    create_subdirs(branch_dir);
    if(EXCEPTION_IS_THROWN)
    {
        goto minivcs_init_from_config_fail_config;
    }
    create_subdirs(file_dir);
    if(EXCEPTION_IS_THROWN)
    {
        goto minivcs_init_from_config_fail_config;
    }
    branch_index_init(project->conf, project->index);
    if(EXCEPTION_IS_THROWN)
    {
        goto minivcs_init_from_config_fail_config;
    }
    free(path);
    free(branch_dir);
    free(file_dir);
    return;

minivcs_init_from_config_fail_config:
    config_destroy(project->conf);
minivcs_init_from_config_fail:
    free(project->conf);
    free(project->index);
    free(branch_dir);
    free(file_dir);
}

void minivcs_open(const char* config_path, struct minivcs_project* project)
{
    project->conf = malloc(sizeof(struct config));
    project->index = malloc(sizeof(struct branch_index));
    char* path = malloc(PATH_MAX + 1);
    if(!project->conf || !project->index || !path)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        goto minivcs_init_from_config_fail;
    }
    config_load(config_path, project->conf);
    if(EXCEPTION_IS_THROWN)
    {
        goto minivcs_init_from_config_fail;
    }
    branch_index_open(project->conf, project->index);
    if(EXCEPTION_IS_THROWN)
    {
        goto minivcs_init_from_config_fail_config;
    }
    free(path);
    return;

    minivcs_init_from_config_fail_config:
    config_destroy(project->conf);
    minivcs_init_from_config_fail:
    free(project->conf);
    free(project->index);
    free(path);
}

void minivcs_destroy(struct minivcs_project* project)
{
    branch_index_destroy(project->index);
    config_destroy(project->conf);
    free(project->index);
    free(project->conf);
}

void minivcs_new_branch(const char* branch_name, struct minivcs_project* project)
{
    branch_index_new_branch(branch_name, project->index);
    if(!EXCEPTION_IS_THROWN)
    {
        branch_index_save(project->index);
    }
}

void minivcs_delete_branch(const char* branch_name, struct minivcs_project* project)
{
    branch_index_delete_branch(branch_name, project->index);
    if(!EXCEPTION_IS_THROWN)
    {
        branch_index_save(project->index);
    }
}

void minivcs_extract(const char* branch_name, const char* destination, struct minivcs_project* project)
{
    struct branch_info branch;
    branch_index_get_branch(branch_name, project->index, &branch);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }
    branch_extract(destination, &branch);
    branch_destroy(&branch);
}

void minivcs_update(const char* branch_name, const char* source, struct minivcs_project* project)
{
    struct branch_info branch;
    branch_index_get_branch(branch_name, project->index, &branch);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }
    branch_update(source, &branch);
    if(EXCEPTION_IS_THROWN)
    {
        branch_destroy(&branch);
        return ;
    }
    branch_save(&branch);
    branch_destroy(&branch);
}
