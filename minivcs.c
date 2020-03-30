#include "minivcs.h"
#include <config/config.h>
#include <branch/branch.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <zconf.h>
#include <string.h>
#include <CEasyException/exception.h>
#include <assert.h>
#include <libgen.h>

static const char* def_config_path = "config";

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
    return;                                                             \
}                                                                       \
((void)(0))

#define INIT_DEFAULT_CONFIG_SET(key, value)                             \
config_set(key, value, &conf);                                          \
if(EXCEPTION_IS_THROWN)                                                 \
{                                                                       \
    goto cleanup;                                                       \
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

void minivcs_generate_config(const char* metadata_path)
{
    struct config conf;
    if(strlen(metadata_path) + 1 + strlen(def_config_path) > PATH_MAX)
    {
        EXCEPTION_THROW(ENAMETOOLONG, "Project path is too long: \"%s\"", metadata_path);
        return;
    }
    char path[PATH_MAX + 1];
    strcpy(path, metadata_path);
    char* path_end = strchr(path, '\0');
    *path_end = '/';
    ++path_end;
    INIT_DEFAULT_MKDIR("branches");
    INIT_DEFAULT_MKDIR("files");
    strcpy(path_end, def_config_path);
    config_init(path, &conf);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }
    
    char real_path[PATH_MAX + 1];
    if(realpath(path, real_path) == NULL)
    {
        EXCEPTION_THROW_NOMSG(errno);
        goto cleanup;
    }
    char* dir_path = dirname(real_path);
    char* dir_path_end = strchr(dir_path, '\0');
    *dir_path_end = '/';
    ++dir_path_end;
    
    strcpy(dir_path_end, "branches/index");
    INIT_DEFAULT_CONFIG_SET("branch_index_path", dir_path);
    strcpy(dir_path_end, "branches");
    INIT_DEFAULT_CONFIG_SET("branch_dir", dir_path);
    INIT_DEFAULT_CONFIG_SET("branch_digest", "sha1");
    INIT_DEFAULT_CONFIG_SET("branch_name_len", "32");
    strcpy(dir_path_end, "files/index");
    INIT_DEFAULT_CONFIG_SET("file_index_path", dir_path);
    strcpy(dir_path_end, "files");
    INIT_DEFAULT_CONFIG_SET("file_dir", dir_path);
    INIT_DEFAULT_CONFIG_SET("file_digest", "sha1");
    INIT_DEFAULT_CONFIG_SET("file_name_len", "32");
    INIT_DEFAULT_CONFIG_SET("cipher", "none");
    INIT_DEFAULT_CONFIG_SET("key_digest", "none");
    INIT_DEFAULT_CONFIG_SET("compression_level", "5");
    config_save(&conf);
    
    cleanup:
    config_destroy(&conf);
}

void minivcs_read_config(const char* metadata_path, struct minivcs_project* project)
{
    minivcs_read_config_only(metadata_path, &project->conf);
    if(EXCEPTION_IS_THROWN)
    {
        config_destroy(&project->conf);
        return;
    }
    project->ctx = ftransform_ctx_extract(&project->conf);
    if(EXCEPTION_IS_THROWN)
    {
        config_destroy(&project->conf);
        return;
    }
    project->index_loaded = false;
}

void minivcs_read_config_only(const char* metadata_path, struct config* conf)
{
    char* config_path = malloc(strlen(metadata_path) + 1 + strlen(def_config_path) + 1);
    if(!config_path)
    {
        EXCEPTION_THROW_NOMSG(errno);
        return;
    }
    strcpy(config_path, metadata_path);
    strcat(config_path, "/");
    strcat(config_path, def_config_path);
    config_load(config_path, conf);
    free(config_path);
}

bool minivcs_need_password(struct minivcs_project* project)
{
    return ftransform_ctx_is_encrypted(&project->ctx);
}

void minivcs_set_password(const char* password, struct minivcs_project* project)
{
    project->ctx.password = password;
}

void minivcs_init_from_config(struct minivcs_project* project)
{
    char* branch_dir = NULL;
    char* file_dir = NULL;
    const char* cbranch_dir = config_get("branch_dir", &project->conf);
    const char* cfile_dir = config_get("file_dir", &project->conf);
    if(!cbranch_dir)
    {
        EXCEPTION_THROW(EINVAL, "%s", "\"branch_dir\" is not found in config");
        goto cleanup;
    }
    if(!cfile_dir)
    {
        EXCEPTION_THROW(EINVAL, "%s", "\"file_dir\" is not found in config");
        goto cleanup;
    }

    branch_dir = malloc(strlen(cbranch_dir)+ 2);
    file_dir = malloc(strlen(cfile_dir)+ 2);
    if(!branch_dir || !file_dir)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        goto cleanup;
    }
    strcpy(branch_dir, cbranch_dir);
    strcat(branch_dir, "/");
    strcpy(file_dir, cfile_dir);
    strcat(file_dir, "/");
    create_subdirs(branch_dir);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup;
    }
    create_subdirs(file_dir);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup;
    }
    branch_index_init(&project->conf, &project->ctx, &project->index);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup;
    }

    project->index_loaded = true;

    cleanup:
    free(branch_dir);
    free(file_dir);
}

void minivcs_open_from_config(struct minivcs_project* project)
{
    branch_index_open(&project->conf, &project->ctx, &project->index);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }
    project->index_loaded = true;
}

void minivcs_destroy(struct minivcs_project* project)
{
    if(project->index_loaded)
    {
        branch_index_destroy(&project->index);
    }
    config_destroy(&project->conf);
}

void minivcs_new_branch(const char* branch_name, struct minivcs_project* project)
{
    assert(project->index_loaded);
    branch_index_new_branch(branch_name, &project->index);
    if(!EXCEPTION_IS_THROWN)
    {
        branch_index_save(&project->index);
    }
}

void minivcs_delete_branch(const char* branch_name, struct minivcs_project* project)
{
    assert(project->index_loaded);
    branch_index_delete_branch(branch_name, &project->index);
    if(!EXCEPTION_IS_THROWN)
    {
        branch_index_save(&project->index);
    }
}

void minivcs_extract(const char* branch_name, const char* destination, struct minivcs_project* project)
{
    assert(project->index_loaded);
    struct branch_info branch;
    branch_index_get_branch(branch_name, &project->index, &branch);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }
    branch_extract(destination, &branch);
    branch_destroy(&branch);
}

void minivcs_update(const char* branch_name, const char* source, struct minivcs_project* project)
{
    assert(project->index_loaded);
    struct branch_info branch;
    branch_index_get_branch(branch_name, &project->index, &branch);
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
