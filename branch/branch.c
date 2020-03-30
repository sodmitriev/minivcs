#include "branch.h"
#include "storage.h"
#include <assert.h>
#include <dirent.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <uthash.h>
#include <zconf.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <file/operations.h>
#include <file/file_transformation_controller.h>
#include <CTransform/CEasyException/exception.h>
#include <CTransform/file/source_file.h>
#include <CTransform/read_write/sink_gets.h>
#include <CTransform/read_write/source_write.h>
#include <CTransform/file/sink_file.h>
#include <CTransform/read_write/sink_read.h>

#define HANDLE_EXCEPTION(lable) if(EXCEPTION_IS_THROWN) goto lable; ((void)(0))

struct branch_index_value
{
    char* file;
    char* name;
    int deleted;
    UT_hash_handle hh;
};

struct branch_info_value
{
    unsigned char* hash;
    char* path;
    struct branch_info_value* next;
};

#define __CHECK_PARAM(name)\
if(!name) {EXCEPTION_THROW(EINVAL, "\"%s\" is not set in config", #name); return;} ((void)(0))

static void branch_index_construct(const struct config* conf, const ftransform_ctx* ctx, struct branch_index* index)
{
    assert(conf);
    assert(index);
    const char* branch_index_path = config_get("branch_index_path", conf);
    const char* branch_dir = config_get("branch_dir", conf);
    const char* branch_digest = config_get("branch_digest", conf);
    const char* branch_name_len = config_get("branch_name_len", conf);
    __CHECK_PARAM(branch_index_path);
    __CHECK_PARAM(branch_dir);
    __CHECK_PARAM(branch_digest);
    __CHECK_PARAM(branch_name_len);

    {
        DIR* dir = opendir(branch_dir);
        if(dir == NULL)
        {
            EXCEPTION_THROW(errno, "Failed to open \"%s\" directory", branch_dir);
            return;
        }
        closedir(dir);
    }

    char* eptr;
    errno = 0;
    index->file_name_size = strtoul(branch_name_len, &eptr, 10);
    if(eptr == branch_name_len || index->file_name_size > NAME_MAX || errno != 0)
    {
        if(errno == 0)
        {
            errno = EINVAL;
        }
        EXCEPTION_THROW(errno, "\"%s\" is not a valid file name length", branch_name_len);
        return;
    }

    index->ctx = ctx;
    index->by_name = NULL;
    index->by_file = NULL;
    index->path = branch_index_path;
    index->branch_dir = branch_dir;
    //index->files will be initialized later
}

static void branch_index_destroy_nofiles(struct branch_index* branch_index)
{
    assert(branch_index);

    {
        struct branch_index_value *val, *tmp;
        HASH_ITER(hh, branch_index->by_name, val, tmp)
        {
            HASH_DEL(branch_index->by_name, val);
            free(val);
        }
    }
    {
        struct branch_index_value *val, *tmp;
        HASH_ITER(hh, branch_index->by_file, val, tmp)
        {
            HASH_DEL(branch_index->by_file, val);
            free(val->file);
            free(val->name);
            free(val);
        }
    }
    branch_index->path = NULL;
}

static char* gen_unique_file(const struct branch_index* index)
{
    unsigned char* raw_name = malloc(index->file_name_size);
    if(!raw_name)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        return NULL;
    }
    char* name = malloc(file_get_name_length(index->file_name_size));
    if(!name)
    {
        goto cleanup_raw;
    }
    struct branch_index_value* val;
    do
    {
        ssize_t err = getrandom(raw_name, index->file_name_size, 0);
        if (err < 0 || (size_t) err != index->file_name_size)
        {
            EXCEPTION_THROW(errno, "%s", "Failed generate random file name");
            goto cleanup_name;
        }

        file_get_name(raw_name, index->file_name_size, name);
        if(EXCEPTION_IS_THROWN)
        {
            goto cleanup_name;
        }
        val = NULL;
        HASH_FIND_STR(index->by_file, name, val);
    } while(val);

    free(raw_name);
    return name;

    cleanup_name:
    free(name);
    cleanup_raw:
    free(raw_name);
    return NULL;
}

void branch_index_new_branch_prepared(const char* name, const char* file, struct branch_index* branch_index)
{
    assert(name);
    assert(file);
    assert(branch_index);

    if(strchr(name, ' ') || strchr(name, '\n'))
    {
        EXCEPTION_THROW(EINVAL, "branch name \"%s\" has invalid format", name);
        return;
    }

    if(strlen(name) + strlen(file) + 2 > LINE_MAX)
    {
        EXCEPTION_THROW(ENAMETOOLONG, "Branch name \"%s\" exceeds length limit", name);
        return;
    }

    char* name_dup = strdup(name);
    if(!name_dup)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        return;
    }
    char* file_dup = strdup(file);
    if(!file_dup)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        goto cleanup_name;
    }

    struct branch_index_value* by_name = NULL;
#ifndef NDEBUG
    HASH_FIND_STR(branch_index->by_name, name, by_name);
    assert(by_name == NULL);
#endif
    by_name = malloc(sizeof(struct branch_index_value));
    if(by_name == NULL)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        goto cleanup_file;
    }
    by_name->name = name_dup;
    by_name->file = file_dup;
    by_name->deleted = 0;

    struct branch_index_value* by_file = NULL;
#ifndef NDEBUG
    HASH_FIND_STR(branch_index->by_file, file, by_file);
    assert(by_file == NULL);
#endif
    by_file = malloc(sizeof(struct branch_index_value));
    if(by_file == NULL)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        goto cleanup_by_name;
    }
    by_file->name = name_dup;
    by_file->file = file_dup;
    by_file->deleted = 0;

    HASH_ADD_STR(branch_index->by_name, name, by_name );
    HASH_ADD_STR(branch_index->by_file, file, by_file );

    return;

    cleanup_by_name:
    free(by_name);
    cleanup_file:
    free(file_dup);
    cleanup_name:
    free(name_dup);
}

void branch_index_init(const struct config* conf, const ftransform_ctx* ctx, struct branch_index* branch_index)
{
    assert(conf);
    assert(branch_index);
    branch_index_construct(conf, ctx, branch_index);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }

    FILE* file = fopen(branch_index->path, "w");
    if(!file)
    {
        EXCEPTION_THROW(errno, "Failed to create branch file \"%s\"", branch_index->path);
        branch_index_destroy_nofiles(branch_index);
        return;
    }

    file_index_init(conf, ctx, &branch_index->files);
    if(EXCEPTION_IS_THROWN)
    {
        unlink(branch_index->path);
        branch_index_destroy_nofiles(branch_index);
        return;
    }
}

static void branch_index_read(struct branch_index* branch_index)
{
    char line[LINE_MAX];

    ftransform_extract_ctl ctl;
    ftransform_extract_ctl_constructor(branch_index->ctx, &ctl);
    HANDLE_EXCEPTION(cleanup_exit);

    source_file src;
    source_file_constructor(&src);
    HANDLE_EXCEPTION(cleanup_ctl);

    source_file_open(branch_index->path, &src);
    HANDLE_EXCEPTION(cleanup_src);

    sink_gets dest;
    sink_gets_constructor(&dest);
    HANDLE_EXCEPTION(cleanup_src);

    controller_set_source((source*) &src, (controller*) &ctl);
    controller_set_sink((sink*) &dest, (controller*) &ctl);

    do
    {
        sink_gets_set(line, sizeof(line), &dest);
        HANDLE_EXCEPTION(cleanup_dest);

        controller_finalize((controller*) &ctl);
        HANDLE_EXCEPTION(cleanup_dest);

        const char *res = sink_gets_get_result(&dest);
        if(!res)
        {
            break;
        }

        size_t len = strlen(res);
        if (len && (res[len - 1] != '\n'))
        {
            EXCEPTION_THROW(EINVAL, "%s", "Corrupted branch index, branch record is too long!");
            goto cleanup_dest;
        }
        char* val_start = strchr(line, ' ');
        if(val_start == NULL)
        {
            EXCEPTION_THROW(EINVAL, "%s", "Corrupted branch index, branch record has no value!");
            goto cleanup_dest;
        }
        *val_start = '\0';
        ++val_start;
        if(*val_start == '\0')
        {
            EXCEPTION_THROW(EINVAL, "%s", "Corrupted branch index, branch record has no value!");
            goto cleanup_dest;
        }
        char* val_end = strchr(val_start, '\n');
        if(val_end != NULL)
        {
            *val_end = '\0';
        }
        branch_index_new_branch_prepared(line, val_start, branch_index);
        HANDLE_EXCEPTION(cleanup_dest);
    } while(controller_get_stage((controller*) &ctl) != controller_stage_done);

    cleanup_dest:
    sink_destructor((sink*) &dest);
    cleanup_src:
    source_destructor((source*) &src);
    cleanup_ctl:
    ftransform_extract_ctl_destructor(&ctl);
    cleanup_exit:
    ((void)(0));
}

void branch_index_open(const struct config* conf, const ftransform_ctx* ctx, struct branch_index* branch_index)
{
    assert(conf);
    assert(branch_index);
    branch_index_construct(conf, ctx, branch_index);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }
    file_index_open(conf, ctx, &branch_index->files);
    if(EXCEPTION_IS_THROWN)
    {
        branch_index_destroy_nofiles(branch_index);
        return;
    }

    branch_index_read(branch_index);
    if(EXCEPTION_IS_THROWN)
    {
        branch_index_destroy(branch_index);
        return;
    }
}

static void branch_index_write(struct branch_index* branch_index)
{
    ftransform_store_ctl ctl;
    ftransform_store_ctl_constructor(branch_index->ctx, &ctl);
    HANDLE_EXCEPTION(cleanup_exit);

    source_write src;
    source_write_constructor(&src);
    HANDLE_EXCEPTION(cleanup_ctl);

    sink_file dest;
    sink_file_constructor(&dest);
    HANDLE_EXCEPTION(cleanup_src);

    sink_file_open(branch_index->path, &dest);
    HANDLE_EXCEPTION(cleanup_dest);

    controller_set_source((source*) &src, (controller*) &ctl);
    controller_set_sink((sink*) &dest, (controller*) &ctl);

    for (struct branch_index_value *val = branch_index->by_name; val != NULL; val = val->hh.next)
    {
        if(val->deleted == 0)
        {
            source_write_set(val->name, 1, strlen(val->name), &src);
            HANDLE_EXCEPTION(cleanup_dest);

            controller_work((controller*) &ctl);
            HANDLE_EXCEPTION(cleanup_dest);

            source_write_set(" ", 1, 1, &src);
            HANDLE_EXCEPTION(cleanup_dest);

            controller_work((controller*) &ctl);
            HANDLE_EXCEPTION(cleanup_dest);

            source_write_set(val->file, 1, strlen(val->file), &src);
            HANDLE_EXCEPTION(cleanup_dest);

            controller_work((controller*) &ctl);
            HANDLE_EXCEPTION(cleanup_dest);

            source_write_set("\n", 1, 1, &src);
            HANDLE_EXCEPTION(cleanup_dest);

            controller_work((controller*) &ctl);
            HANDLE_EXCEPTION(cleanup_dest);
        }
    }

    source_write_set(NULL, 1, 0, &src);
    HANDLE_EXCEPTION(cleanup_dest);

    controller_finalize((controller*) &ctl);
    HANDLE_EXCEPTION(cleanup_dest);

    assert(controller_get_stage((controller*) &ctl) == controller_stage_done);

    cleanup_dest:
    sink_destructor((sink*) &dest);
    cleanup_src:
    source_destructor((source*) &src);
    cleanup_ctl:
    ftransform_store_ctl_destructor(&ctl);
    cleanup_exit:
    ((void)(0));
}

static void branch_index_allocate_files(struct branch_index* index)
{
    char name[PATH_MAX + 1];
    assert(sizeof(name) > strlen(index->branch_dir));
    strcpy(name, index->branch_dir);
    strcat(name, "/");
    char* name_end = strchr(name, '\0');
    assert(name_end);

    struct branch_index_value *val, *tmp;
    HASH_ITER(hh, index->by_name, val, tmp)
    {
        if(val->deleted == 1)
        {
            struct branch_info branch;
            branch_index_get_branch(val->name, index, &branch);
            if(!EXCEPTION_IS_THROWN)
            {
                branch.files = NULL;
                branch_save(&branch);
                branch_destroy(&branch);
            }

            struct branch_index_value* by_file_val;
            HASH_FIND_STR(index->by_file, val->file, by_file_val);
            assert(by_file_val);
            HASH_DEL(index->by_name, val);
            HASH_DEL(index->by_file, by_file_val);
            if(!EXCEPTION_IS_THROWN)
            {
                strcpy(name_end, val->file);
                unlink(name);
            }
            free(val->file);
            free(val->name);
            free(val);
            free(by_file_val);
            EXCEPTION_CLEAR();
        }
    }
}

void branch_index_save(struct branch_index* index)
{
    assert(index);
    const char* storage = ".~branch_index";

    store_file(storage, index->path);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }

    branch_index_write(index);
    if(EXCEPTION_IS_THROWN)
    {
        restore_file(storage, index->path);
        return;
    }

    branch_index_allocate_files(index);
    if(EXCEPTION_IS_THROWN)
    {
        restore_file(storage, index->path);
        return;
    }


    reset_storage(storage);
}

void branch_index_destroy(struct branch_index* index)
{
    branch_index_destroy_nofiles(index);
    file_index_destroy(&index->files);
}

void branch_index_new_branch(const char* name, struct branch_index* branch_index)
{
    assert(name);
    assert(branch_index);
    char* file = gen_unique_file(branch_index);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }
    branch_index_new_branch_prepared(name, file, branch_index);
    free(file);
}

void branch_index_delete_branch(const char* name, struct branch_index* branch_index)
{
    struct branch_index_value* val = NULL;
    HASH_FIND_STR(branch_index->by_name, name, val);
    if(!val)
    {
        EXCEPTION_THROW(EINVAL, "Branch \"%s\" does not exist", name);
        return;
    }
    val->deleted = 1;
}

const char* branch_index_find(const char* name, struct branch_index* index)
{
    struct branch_index_value* val = NULL;
    HASH_FIND_STR(index->by_name, name, val);
    if(!val)
    {
        return NULL;
    }
    return val->file;
}

size_t branch_index_count(const struct branch_index* index)
{
    assert(index);
    return HASH_COUNT(index->by_name);
}

void branch_index_get_names(const char** names, const struct branch_index* index)
{
    assert(index);
    for (struct branch_index_value* val = index->by_name; val != NULL; val = val->hh.next)
    {
        *names = val->name;
        ++names;
    }
}

static void branch_create(struct branch_info* branch)
{
    FILE* file = fopen(branch->path, "w");
    if(!file)
    {
        EXCEPTION_THROW(errno, "Failed to open branch file \"%s\"", branch->path);
        return;
    }
    fclose(file);
    branch->files = NULL;
    branch->files_saved = NULL;
}

static void branch_read(struct branch_info* branch)
{
    size_t hash_size = file_index_hash_size(branch->index);
    unsigned char* hash_buf = malloc(hash_size);
    if(!hash_buf)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        return;
    }
    char* path_buf = malloc(PATH_MAX + 1);
    if(!path_buf)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        goto cleanup_hash;
    }

    assert(branch->files == NULL);

    ftransform_extract_ctl ctl;
    ftransform_extract_ctl_constructor(branch->ctx, &ctl);
    HANDLE_EXCEPTION(cleanup_path);

    source_file src;
    source_file_constructor(&src);
    HANDLE_EXCEPTION(cleanup_ctl);

    source_file_open(branch->path, &src);
    HANDLE_EXCEPTION(cleanup_src);

    sink_gets dest_gets;
    sink_gets_constructor(&dest_gets);
    HANDLE_EXCEPTION(cleanup_src);

    sink_read dest_read;
    sink_read_constructor(&dest_read);
    HANDLE_EXCEPTION(cleanup_dest_gets);

    controller_set_source((source*) &src, (controller*) &ctl);

    do
    {

        sink_read_set(hash_buf, 1, hash_size, &dest_read);
        HANDLE_EXCEPTION(cleanup_dest_read);

        controller_set_sink((sink*) &dest_read, (controller*) &ctl);

        controller_finalize((controller*) &ctl);
        HANDLE_EXCEPTION(cleanup_dest_read);

        if(controller_get_stage((controller*) &ctl) == controller_stage_done)
        {
            break;
        }

        sink_gets_set(path_buf, PATH_MAX + 1, &dest_gets);
        HANDLE_EXCEPTION(cleanup_dest_read);

        controller_set_sink((sink*) &dest_gets, (controller*) &ctl);

        controller_finalize((controller*) &ctl);
        HANDLE_EXCEPTION(cleanup_dest_read);

        char* nl = strchr(path_buf, '\n');
        if(nl)
        {
            *nl = 0;
        }
        struct branch_info_value* val = malloc(sizeof(struct branch_info_value));
        if(!val)
        {
            EXCEPTION_THROW_NOMSG(ENOMEM);
            goto cleanup_dest_read;
        }
        val->hash = malloc(hash_size);
        if(!val->hash)
        {
            EXCEPTION_THROW_NOMSG(ENOMEM);
            free(val);
            goto cleanup_dest_read;
        }
        memcpy(val->hash, hash_buf, hash_size);
        val->path = strdup(path_buf);
        if(!val->path)
        {
            EXCEPTION_THROW_NOMSG(ENOMEM);
            free(val->hash);
            free(val);
            goto cleanup_dest_read;
        }
        val->next = branch->files;
        branch->files = val;
    } while(controller_get_stage((controller*) &ctl) != controller_stage_done);

    cleanup_dest_read:
    sink_destructor((sink*) &dest_gets);
    cleanup_dest_gets:
    sink_destructor((sink*) &dest_read);
    cleanup_src:
    source_destructor((source*) &src);
    cleanup_ctl:
    ftransform_extract_ctl_destructor(&ctl);
    cleanup_path:
    free(path_buf);
    cleanup_hash:
    free(hash_buf);
}

static void branch_open(struct branch_info* branch)
{
    branch->files = NULL;

    branch_read(branch);
    if(EXCEPTION_IS_THROWN)
    {
        branch_destroy(branch);
        return;
    }

    branch->files_saved = branch->files;
}

void branch_index_get_branch(const char* name, struct branch_index* index, struct branch_info* branch)
{
    assert(name);
    assert(index);
    assert(branch);
    const char* file = branch_index_find(name, index);
    if(!file)
    {
        EXCEPTION_THROW(EINVAL, "Branch \"%s\" does not exist", name);
        return;
    }
    branch->path = malloc(strlen(index->branch_dir) + strlen(file) + 2);
    if(!branch->path)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        return;
    }
    branch->ctx = index->ctx;
    strcpy(branch->path, index->branch_dir);
    strcat(branch->path, "/");
    strcat(branch->path, file);
    branch->index = &index->files;
    branch->branch_dir = index->branch_dir;
    branch->imported_dir = NULL;
    struct stat file_stat;
    int err = stat(branch->path, &file_stat);
    if(err == 0 && S_ISREG(file_stat.st_mode))
    {
        branch_open(branch);
        if(EXCEPTION_IS_THROWN)
        {
            free(branch->path);
        }
        return;
    }
    else if(err < 0 && errno == ENOENT)
    {
        branch_create(branch);
        if(EXCEPTION_IS_THROWN)
        {
            free(branch->path);
        }
        return;
    }
    else if(err == 0)
    {
        EXCEPTION_THROW(EINVAL, "File \"%s\" is not a regular file", branch->path);
        free(branch->path);
        return;
    }
    else
    {
        EXCEPTION_THROW(errno, "Failed to open \"%s\"", branch->path);
        free(branch->path);
        return;
    }
}

static void destroy_list(struct branch_info_value* head)
{
    struct branch_info_value *val;
    while(head)
    {
        val = head;
        head = head->next;
        free(val->path);
        free(val->hash);
        free(val);
    }
}

static void branch_write(struct branch_info* branch)
{
    size_t hash_size = file_index_hash_size(branch->index);

    ftransform_store_ctl ctl;
    ftransform_store_ctl_constructor(branch->ctx, &ctl);
    HANDLE_EXCEPTION(cleanup_exit);

    source_write src;
    source_write_constructor(&src);
    HANDLE_EXCEPTION(cleanup_ctl);

    sink_file dest;
    sink_file_constructor(&dest);
    HANDLE_EXCEPTION(cleanup_src);

    sink_file_open(branch->path, &dest);
    HANDLE_EXCEPTION(cleanup_dest);

    controller_set_source((source*) &src, (controller*) &ctl);
    controller_set_sink((sink*) &dest, (controller*) &ctl);

    for (struct branch_info_value *val = branch->files; val != NULL; val = val->next)
    {
        source_write_set(val->hash, 1, hash_size, &src);
        HANDLE_EXCEPTION(cleanup_dest);

        controller_work((controller*) &ctl);
        HANDLE_EXCEPTION(cleanup_dest);

        size_t len = strlen(val->path);

        source_write_set(val->path, 1, len, &src);
        HANDLE_EXCEPTION(cleanup_dest);

        controller_work((controller*) &ctl);
        HANDLE_EXCEPTION(cleanup_dest);

        source_write_set("\n", 1, 1, &src);
        HANDLE_EXCEPTION(cleanup_dest);

        controller_work((controller*) &ctl);
        HANDLE_EXCEPTION(cleanup_dest);
    }

    source_write_set(NULL, 1, 0, &src);
    HANDLE_EXCEPTION(cleanup_dest);

    controller_finalize((controller*) &ctl);
    HANDLE_EXCEPTION(cleanup_dest);

    assert(controller_get_stage((controller*) &ctl) == controller_stage_done);

    cleanup_dest:
    sink_destructor((sink*) &dest);
    cleanup_src:
    source_destructor((source*) &src);
    cleanup_ctl:
    ftransform_store_ctl_destructor(&ctl);
    cleanup_exit:
    ((void)(0));
}

static void branch_update_refs(struct branch_info* branch)
{
    for (struct branch_info_value *val = branch->files_saved; val != NULL; val = val->next)
    {
        if(val->path[strlen(val->path) - 1] != '/')
        {
            struct file_info *info = file_index_find_by_hash(val->hash, branch->index);
            if(EXCEPTION_IS_THROWN)
            {
                return;
            }
            assert(info);
            file_info_remove_ref(info);
        }
    }
    for (struct branch_info_value *val = branch->files; val != NULL; val = val->next)
    {
        if(val->path[strlen(val->path) - 1] != '/')
        {
            struct file_info *info = file_index_find_by_hash(val->hash, branch->index);
            if (info && !EXCEPTION_IS_THROWN)
            {
                file_info_add_ref(info);
            }
            else if(EXCEPTION_IS_THROWN)
            {
                return;
            }
            else
            {
                info = file_index_insert(val->hash, branch->index);
                if (EXCEPTION_IS_THROWN)
                {
                    return;
                }
                file_info_add_ref(info);
                char *fname = malloc(file_get_name_length(file_index_name_size(branch->index)));
                if(!fname)
                {
                    EXCEPTION_THROW_NOMSG(errno);
                    return;
                }
                file_get_name(file_info_get_name(info), file_index_name_size(branch->index), fname);
                if (EXCEPTION_IS_THROWN)
                {
                    free(fname);
                    return;
                }
                char *full_path = malloc(strlen(val->path) + 2 + strlen(branch->imported_dir));
                if (!full_path)
                {
                    EXCEPTION_THROW_NOMSG(errno);
                    free(fname);
                    return;
                }
                char *full_name = malloc(strlen(fname) + 2 + strlen(file_index_file_dir(branch->index)));
                if (!full_name)
                {
                    EXCEPTION_THROW_NOMSG(errno);
                    free(fname);
                    free(full_path);
                    return;
                }
                strcpy(full_path, branch->imported_dir);
                strcat(full_path, "/");
                strcat(full_path, val->path);
                strcpy(full_name, file_index_file_dir(branch->index));
                strcat(full_name, "/");
                strcat(full_name, fname);
                file_store(full_path, full_name, branch->ctx);
                if (EXCEPTION_IS_THROWN)
                {
                    EXCEPTION_THROW_NOMSG(errno);
                    free(fname);
                    free(full_path);
                    free(full_name);
                    return;
                }
                free(fname);
                free(full_path);
                free(full_name);
            }
        }
    }
}

void branch_save(struct branch_info* branch)
{
    assert(branch);
    if(branch->files_saved == branch->files)
    {
        return;
    }
    assert(branch->imported_dir || branch->files == NULL);
    const char* storage = ".~branch";

    store_file(storage, branch->path);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }

    branch_write(branch);
    if(EXCEPTION_IS_THROWN)
    {
        restore_file(storage, branch->path);
        return;
    }


    branch_update_refs(branch);
    if(EXCEPTION_IS_THROWN)
    {
        fprintf(stderr, "%s\n", EXCEPTION_MSG);
        restore_file(storage, branch->path);
        perror("Critical error, aborting to prevent data loss");
        abort();
    }


    file_index_save(branch->index);
    if(EXCEPTION_IS_THROWN)
    {
        fprintf(stderr, "%s\n", EXCEPTION_MSG);
        restore_file(storage, branch->path);
        perror("Critical error, aborting to prevent data loss");
        abort();
    }

    reset_storage(storage);
    destroy_list(branch->files_saved);
    branch->files_saved = branch->files;
}

void branch_destroy(struct branch_info* branch)
{
    assert(branch);
    free(branch->path);
    if(branch->files_saved != branch->files)
    {
        destroy_list(branch->files_saved);
    }
    destroy_list(branch->files);
    if(branch->imported_dir)
    {
        free(branch->imported_dir);
    }
    branch->path = NULL;
}

static void create_subdirs(char* path)
{
    assert(path);
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

void branch_extract(const char* dst_dir, const struct branch_info* branch)
{
    assert(branch);
    assert(dst_dir);
    size_t to_dir_path_len = strlen(dst_dir);
    size_t from_dir_path_len = strlen(branch->branch_dir);
    if(to_dir_path_len + 2 > PATH_MAX || from_dir_path_len + 2 > PATH_MAX)
    {
        EXCEPTION_THROW(ENAMETOOLONG, "%s", "Destination path is too long");
        return;
    }
    char* to = malloc(PATH_MAX + 1);
    if(!to)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        return;
    }
    char* from = malloc(PATH_MAX + 1);
    if(!from)
    {
        free(to);
        EXCEPTION_THROW_NOMSG(ENOMEM);
        return;
    }
    strcpy(to, dst_dir);
    strcat(to, "/");
    strcpy(from, file_index_file_dir(branch->index));
    strcat(from, "/");
    create_subdirs(to);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup;
    }

    char* to_end = strchr(to, '\0');
    char* from_end = strchr(from, '\0');
    assert(to_end);
    assert(from_end);

    struct branch_info_value* val = NULL;
    for (val = branch->files_saved; val != NULL; val = val->next)
    {
        if(to_dir_path_len + 1 + strlen(val->path) > PATH_MAX)
        {
            EXCEPTION_THROW(ENAMETOOLONG, "%s", "Destination path is too long");
            goto cleanup;
        }
        if(val->path[strlen(val->path) - 1] == '/')
        {
            *to_end = '\0';
            strcat(to_end, val->path);
            create_subdirs(to);
            if (EXCEPTION_IS_THROWN)
            {
                goto cleanup;
            }
        }
        else
        {
            struct file_info *info = file_index_find_by_hash(val->hash, branch->index);
            if (EXCEPTION_IS_THROWN)
            {
                goto cleanup;
            }
            else if(!info)
            {
                EXCEPTION_THROW(ENOENT, "%s", "Data is corrupted, file hash is not found in file index");
                goto cleanup;
            }
            char *orig_name = malloc(file_get_name_length(file_index_name_size(branch->index)));
            if(!orig_name)
            {
                EXCEPTION_THROW_NOMSG(ENOMEM);
                goto cleanup;
            }
            file_get_name(file_info_get_name(info), file_index_name_size(branch->index), orig_name);
            if (EXCEPTION_IS_THROWN)
            {
                free(orig_name);
                goto cleanup;
            }
            if (from_dir_path_len + 1 + strlen(orig_name) > PATH_MAX)
            {
                free(orig_name);
                EXCEPTION_THROW(ENAMETOOLONG, "%s", "Destination path is too long");
                goto cleanup;
            }
            *to_end = '\0';
            *from_end = '\0';
            strcat(to_end, val->path);
            strcat(from_end, orig_name);
            free(orig_name);
            create_subdirs(to);
            if (EXCEPTION_IS_THROWN)
            {
                goto cleanup;
            }
            file_extract(from, to, branch->ctx);
            if(EXCEPTION_IS_THROWN)
            {
                goto cleanup;
            }
        }
    }

    cleanup:
    free(to);
    free(from);
}

static void branch_put_dir(struct branch_info* branch, struct branch_info_value** htab, char* src_dir, size_t orig_len)
{
    char* dir_end = strchr(src_dir, '\0');
    assert(dir_end);
    size_t hash_size = file_index_hash_size(branch->index);
    DIR *dir = opendir(src_dir);
    if (dir == NULL)
    {
        EXCEPTION_THROW(errno, "Failed to open directory \"%s\"", src_dir);
        return;
    }
    strcat(src_dir, "/");
    struct dirent* dirent;
    int empty = 1;
    for(dirent = readdir(dir); dirent != NULL; dirent = readdir(dir))
    {
        struct stat file_stat;
        if(strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0)
        {
            continue;
        }
        empty = 0;
        dir_end[1] = '\0';
        strcat(src_dir, dirent->d_name);
        int err = stat(src_dir, &file_stat);
        if(err < 0)
        {
            EXCEPTION_THROW(errno, "Failed to stat file \"%s\"", src_dir);
            *dir_end = '\0';
            closedir(dir);
            return;
        }
        if(S_ISREG(file_stat.st_mode))
        {
            char* namedup = strdup(src_dir + orig_len + 1);
            if(!namedup)
            {
                EXCEPTION_THROW_NOMSG(errno);
                *dir_end = '\0';
                closedir(dir);
                return;
            }
            unsigned char* fhash = malloc(hash_size);
            if(!fhash)
            {
                EXCEPTION_THROW_NOMSG(errno);
                *dir_end = '\0';
                closedir(dir);
                free(namedup);
                return;
            }
            file_hash(src_dir, file_index_config(branch->index), fhash);
            if(EXCEPTION_IS_THROWN)
            {
                *dir_end = '\0';
                closedir(dir);
                free(namedup);
                free(fhash);
                return;
            }
            struct branch_info_value* val = malloc(sizeof(struct branch_info_value));
            if(!val)
            {
                EXCEPTION_THROW_NOMSG(errno);
                *dir_end = '\0';
                closedir(dir);
                free(namedup);
                free(fhash);
                return;
            }
            val->hash = fhash;
            val->path = namedup;
            val->next = *htab;
            *htab = val;
        }
        else if(S_ISDIR(file_stat.st_mode))
        {
            branch_put_dir(branch, htab, src_dir, orig_len);
        }
    }
    closedir(dir);
    if(empty)
    {
        dir_end[1] = '\0';
        char* namedup;
        if(*(src_dir + orig_len + 1) == '\0')
        {
            namedup = strdup("/");
        }
        else
        {
            namedup = strdup(src_dir + orig_len + 1);
        }
        if(!namedup)
        {
            *dir_end = '\0';
            EXCEPTION_THROW_NOMSG(errno);
            return;
        }
        if(namedup[0] == '\0')
        {
            namedup[0] = '/';
            namedup[1] = '\0';
        }
        unsigned char* fhash = malloc(hash_size);
        if(!fhash)
        {
            *dir_end = '\0';
            free(namedup);
            EXCEPTION_THROW_NOMSG(errno);
            return;
        }
        memset(fhash, 0, hash_size);
        struct branch_info_value* val = malloc(sizeof(struct branch_info_value));
        if(!val)
        {
            *dir_end = '\0';
            free(namedup);
            free(fhash);
            EXCEPTION_THROW_NOMSG(errno);
            return;
        }
        val->hash = fhash;
        val->path = namedup;
        val->next = *htab;
        *htab = val;
    }
    *dir_end = '\0';
}

void branch_update(const char* src_dir, struct branch_info* branch)
{
    char* impdir = strdup(src_dir);
    if(!impdir)
    {
        EXCEPTION_THROW_NOMSG(errno);
        return;
    }
    char* name = malloc(PATH_MAX + 1);
    if(!name)
    {
        free(impdir);
        EXCEPTION_THROW_NOMSG(errno);
        return;
    }
    strcpy(name, src_dir);
    struct branch_info_value* htab = NULL;
    branch_put_dir(branch, &htab, name, strlen(src_dir));
    free(name);
    if(EXCEPTION_IS_THROWN)
    {
        free(impdir);
        destroy_list(htab);
        return;
    }
    if(branch->files_saved != branch->files)
    {
        destroy_list(branch->files);
    }
    branch->files = htab;
    if(branch->imported_dir)
    {
        free(branch->imported_dir);
    }
    branch->imported_dir = impdir;
}
