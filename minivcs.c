#include "minivcs.h"

#include <config/config.h>
#include <branch/branch.h>

#include <CEasyException/exception.h>
#include <CTransform/read_write/source_write.h>
#include <CTransform/read_write/sink_read.h>
#include <CTransform/file/source_file.h>
#include <CTransform/file/sink_file.h>
#include <CTransform/crypto/transformation_encrypt.h>
#include <CTransform/crypto/transformation_decrypt.h>
#include <CTransform/crypto/transformation_hash.h>
#include <CTransform/controller.h>
#include <openssl/evp.h>

#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <zconf.h>
#include <string.h>
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

static size_t digest_hash_size(const char* digest)
{
    const EVP_MD *md;

    md = EVP_get_digestbyname(digest);

    if(!md)
    {
        EXCEPTION_THROW(EINVAL, "File digest \"%s\" does not exist", digest);
        return -1;
    }
    return EVP_MD_size(md);
}

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
    strcpy(dir_path_end, "passcheck");
    INIT_DEFAULT_CONFIG_SET("password_check", dir_path);
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

static void save_password(struct minivcs_project* project)
{
    if(!minivcs_need_password(project))
    {
        return;
    }

    const char* passcheck = config_get("password_check", &project->conf);
    if(!passcheck)
    {
        EXCEPTION_THROW(EINVAL, "%s", "\"password_check\" is not found in config");
        return;
    }

    const char* cipher = config_get("cipher", &project->conf);
    if(!cipher)
    {
        EXCEPTION_THROW(EINVAL, "%s", "\"cipher\" is not found in config");
        return;
    }

    const char* key_digest = config_get("key_digest", &project->conf);
    if(!key_digest)
    {
        EXCEPTION_THROW(EINVAL, "%s", "\"key_digest\" is not found in config");
        return;
    }

    source_write src;
    transformation_hash hash;
    transformation_encrypt encrypt;
    sink_file dest;

    controller ctl;

    source_write_constructor(&src);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }

    source_write_set(project->ctx.password, 1, strlen(project->ctx.password), &src);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_src;
    }

    transformation_hash_constructor(key_digest, &hash);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_src;
    }

    transformation_encrypt_constructor(cipher, key_digest, project->ctx.password, &encrypt);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_hash;
    }

    sink_file_constructor(&dest);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_encrypt;
    }

    sink_file_open(passcheck, &dest);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_sink;
    }

    controller_constructor(&ctl);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_sink;
    }

    controller_add_transformation((transformation*) &hash, &ctl);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_ctl;
    }

    controller_add_transformation((transformation*) &encrypt, &ctl);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_ctl;
    }

    controller_set_source((source*) &src, &ctl);
    controller_set_sink((sink*) &dest, &ctl);

    controller_finalize(&ctl);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_ctl;
    }

    assert(controller_get_stage(&ctl) == controller_stage_done);

    cleanup_ctl:
    controller_destructor(&ctl);
    cleanup_sink:
    sink_destructor((sink*) &dest);
    cleanup_encrypt:
    transformation_destructor((transformation*) &encrypt);
    cleanup_hash:
    transformation_destructor((transformation*) &hash);
    cleanup_src:
    source_destructor((source*) &src);
}

static void hash_password(const char* password, const char* digest, char* res, size_t size)
{
    source_write src;
    transformation_hash hash;
    sink_read dest;

    controller ctl;

    source_write_constructor(&src);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }

    source_write_set(password, 1, strlen(password), &src);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_src;
    }

    transformation_hash_constructor(digest, &hash);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_src;
    }

    sink_read_constructor(&dest);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_hash;
    }

    sink_read_set(res, 1, size, &dest);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_sink;
    }

    controller_constructor(&ctl);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_sink;
    }

    controller_add_transformation((transformation*) &hash, &ctl);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_ctl;
    }

    controller_set_source((source*) &src, &ctl);
    controller_set_sink((sink*) &dest, &ctl);

    controller_finalize(&ctl);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_ctl;
    }

    assert(controller_get_stage(&ctl) == controller_stage_done);

    cleanup_ctl:
    controller_destructor(&ctl);
    cleanup_sink:
    sink_destructor((sink*) &dest);
    cleanup_hash:
    transformation_destructor((transformation*) &hash);
    cleanup_src:
    source_destructor((source*) &src);
}

static void read_cmp_password(const char* password, const char* digest, const char* cipher, const char* path,
                              char* res, size_t size)
{
    source_file src;
    transformation_decrypt decrypt;
    sink_read dest;

    controller ctl;

    source_file_constructor(&src);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }

    source_file_open(path, &src);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_src;
    }

    transformation_decrypt_constructor(cipher, digest, password, &decrypt);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_src;
    }

    sink_read_constructor(&dest);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_decrypt;
    }

    sink_read_set(res, 1, size, &dest);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_sink;
    }

    controller_constructor(&ctl);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_sink;
    }

    controller_add_transformation((transformation*) &decrypt, &ctl);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_ctl;
    }

    controller_set_source((source*) &src, &ctl);
    controller_set_sink((sink*) &dest, &ctl);

    controller_finalize(&ctl);
    if(EXCEPTION_IS_THROWN)
    {
        EXCEPTION_THROW_NOMSG(EKEYREJECTED);
        goto cleanup_ctl;
    }

    assert(controller_get_stage(&ctl) == controller_stage_done);

    cleanup_ctl:
    controller_destructor(&ctl);
    cleanup_sink:
    sink_destructor((sink*) &dest);
    cleanup_decrypt:
    transformation_destructor((transformation*) &decrypt);
    cleanup_src:
    source_destructor((source*) &src);
}

static bool cmp_password(struct minivcs_project* project)
{
    if(!minivcs_need_password(project))
    {
        return true;
    }

    const char* passcheck = config_get("password_check", &project->conf);
    if(!passcheck)
    {
        EXCEPTION_THROW(EINVAL, "%s", "\"password_check\" is not found in config");
        return false;
    }

    const char* cipher = config_get("cipher", &project->conf);
    if(!cipher)
    {
        EXCEPTION_THROW(EINVAL, "%s", "\"cipher\" is not found in config");
        return false;
    }

    const char* key_digest = config_get("key_digest", &project->conf);
    if(!key_digest)
    {
        EXCEPTION_THROW(EINVAL, "%s", "\"key_digest\" is not found in config");
        return false;
    }

    bool ret = false;

    size_t hash_size = digest_hash_size(key_digest);

    char* pass_hash = malloc(hash_size);
    if(!pass_hash)
    {
        EXCEPTION_THROW_NOMSG(errno);
        goto cleanup_exit;
    }

    char* cmp_hash = malloc(hash_size);
    if(!cmp_hash)
    {
        EXCEPTION_THROW_NOMSG(errno);
        goto cleanup_hash;
    }

    hash_password(project->ctx.password, key_digest, pass_hash, hash_size);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_cmp;
    }

    read_cmp_password(project->ctx.password, key_digest, cipher, passcheck, cmp_hash, hash_size);
    if(EXCEPTION_IS_THROWN)
    {
        if(EXCEPTION_ERROR == EKEYREJECTED)
        {
            EXCEPTION_CLEAR(); //Failed to encrypt with provided password
        }
        goto cleanup_cmp;
    }

    ret = (memcmp(pass_hash, cmp_hash, hash_size) == 0);

    cleanup_cmp:
    free(cmp_hash);
    cleanup_hash:
    free(pass_hash);
    cleanup_exit:
    return ret;
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

    save_password(project);
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
    bool match = cmp_password(project);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }

    if(!match)
    {
        EXCEPTION_THROW(EINVAL, "%s", "Incorrect password");
        return;
    }

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
