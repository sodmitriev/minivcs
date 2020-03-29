#include "files.h"
#include "storage.h"

#include <file/operations.h>
#include <file/file_transformation_controller.h>

#include <CTransform/CEasyException/exception.h>
#include <uthash.h>

#include <assert.h>
#include <limits.h>
#include <sys/random.h>
#include <dirent.h>
#include <errno.h>
#include <zconf.h>
#include <CTransform/file/source_file.h>
#include <CTransform/read_write/sink_read.h>
#include <CTransform/read_write/source_write.h>
#include <CTransform/file/sink_file.h>

#define HANDLE_EXCEPTION(lable) if(EXCEPTION_IS_THROWN) goto lable; ((void)(0))

struct file_info
{
    unsigned char* hash;
    unsigned char* name;
    size_t ref_count;
};

struct file_index_value_by_hash
{
    char* hash;
    struct file_info* value;
    UT_hash_handle hh;
};

struct file_index_value_by_name
{
    char* name;
    struct file_info* value;
    UT_hash_handle hh;
};

static unsigned char* gen_unique_name(const struct file_index* index)
{
    unsigned char* name = malloc(index->name_size);
    if(!name)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        return NULL;
    }
    struct file_info* info = NULL;
    do
    {
        ssize_t err = getrandom(name, index->name_size, 0);
        if (err < 0 || (size_t) err != index->name_size)
        {
            EXCEPTION_THROW(errno, "%s", "Failed to generate file name");
            free(name);
            return NULL;
        }
        info = file_index_find_by_name(name, index);
        if(EXCEPTION_IS_THROWN)
        {
            free(name);
            return NULL;
        }
    } while(info);
    return name;
}

#define __CHECK_PARAM(name)\
if(!name) {EXCEPTION_THROW(EINVAL, "\"%s\" is not set in config", #name); return;} ((void)(0))

static void file_index_construct(const struct config* conf, const ftransform_ctx* ctx, struct file_index* index)
{
    assert(conf);
    assert(index);
    const char* file_index_path = config_get("file_index_path", conf);
    const char* file_dir = config_get("file_dir", conf);
    const char* file_name_len = config_get("file_name_len", conf);
    __CHECK_PARAM(file_index_path);
    __CHECK_PARAM(file_dir);
    __CHECK_PARAM(file_name_len);

    {
        DIR* dir = opendir(file_dir);
        if(dir == NULL)
        {
            EXCEPTION_THROW(errno, "Failed to open \"%s\" directory", file_dir);
            return;
        }
        closedir(dir);
    }

    char* eptr;
    errno = 0;
    index->name_size = strtoul(file_name_len, &eptr, 10);
    if(eptr == file_name_len || index->name_size > NAME_MAX || errno != 0)
    {
        if(errno == 0)
        {
            errno = EINVAL;
        }
        EXCEPTION_THROW(errno, "\"%s\" is not a valid file name length", file_name_len);
        return;
    }

    index->by_hash = NULL;
    index->by_name = NULL;
    index->path = file_index_path;
    index->file_dir = file_dir;
    index->conf = conf;
    index->ctx = ctx;
}

void file_index_init(const struct config* conf, const ftransform_ctx* ctx, struct file_index* index)
{
    assert(conf);
    assert(index);

    file_index_construct(conf, ctx, index);
    HANDLE_EXCEPTION(cleanup_exit);

    FILE* f = fopen(index->path, "w");
    if(!f)
    {
        EXCEPTION_THROW(errno, "Failed to create index file \"%s\"", index->path);
        HANDLE_EXCEPTION(cleanup_index);
    }

    fclose(f);
    return;

    cleanup_index:
    file_index_destroy(index);
    cleanup_exit:
    ((void)(0));
}

static struct file_info* file_index_insert_prepared(const unsigned char* hash, const unsigned char* name, struct file_index* index)
{
    assert(hash);
    assert(name);
    assert(index);

    size_t hsize = file_hash_size(index->conf);
    if(EXCEPTION_IS_THROWN)
    {
        return NULL;
    }

    char* hash_encoded;
    char* name_encoded;

    hash_encoded = malloc(file_get_name_length(hsize));
    if(!hash_encoded)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        return NULL;
    }

    name_encoded = malloc(file_get_name_length(index->name_size));
    if(!name_encoded)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        goto cleanup_hash;
    }

    file_get_name(hash, hsize, hash_encoded);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_name;
    }
    file_get_name(name, index->name_size, name_encoded);
    if(EXCEPTION_IS_THROWN)
    {
        goto cleanup_name;
    }

    struct file_info* info = malloc(sizeof(struct file_info));
    if(!info)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        goto cleanup_name;
    }

    info->hash = malloc(hsize);
    if(!info->hash)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        goto cleanup_info;
    }
    memcpy(info->hash, hash, hsize);

    info->name = malloc(index->name_size);
    if(!info->name)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        goto cleanup_info_hash;
    }
    memcpy(info->name, name, index->name_size);

    info->ref_count = 0;

    struct file_index_value_by_hash* by_hash = NULL;
#ifndef NDEBUG
    HASH_FIND_STR(index->by_hash, hash_encoded, by_hash);
    assert(by_hash == NULL);
#endif
    by_hash = malloc(sizeof(struct file_index_value_by_hash));
    if(by_hash == NULL)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        goto cleanup_info_name;
    }
    by_hash->hash = hash_encoded;
    by_hash->value = info;

    struct file_index_value_by_name* by_name = NULL;
#ifndef NDEBUG
    HASH_FIND_STR(index->by_name, name_encoded, by_name);
    assert(by_name == NULL);
#endif
    by_name = malloc(sizeof(struct file_index_value_by_name));
    if(by_name == NULL)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        goto cleanup_by_hash;
    }
    by_name->name = name_encoded;
    by_name->value = info;

    HASH_ADD_STR(index->by_hash, hash, by_hash );
    HASH_ADD_STR(index->by_name, name, by_name );

    return info;

    cleanup_by_hash:
    free(by_hash);
    cleanup_info_name:
    free(info->name);
    cleanup_info_hash:
    free(info->hash);
    cleanup_info:
    free(info);
    cleanup_name:
    free(name_encoded);
    cleanup_hash:
    free(hash_encoded);
    return NULL;
}

static void file_index_read(struct file_index* index)
{
    size_t hsize = file_hash_size(index->conf);
    HANDLE_EXCEPTION(cleanup_exit);

    const size_t row_size = hsize + index->name_size + sizeof(((struct file_info*)(0))->ref_count);

    ftransform_extract_ctl ctl;
    ftransform_extract_ctl_constructor(index->ctx, &ctl);
    HANDLE_EXCEPTION(cleanup_exit);

    source_file src;

    source_file_constructor(&src);
    HANDLE_EXCEPTION(cleanup_ctl);

    source_file_open(index->path, &src);
    HANDLE_EXCEPTION(cleanup_src);

    sink_read dest;

    sink_read_constructor(&dest);
    HANDLE_EXCEPTION(cleanup_src);

    controller_set_source((source*) &src, (controller*) &ctl);
    controller_set_sink((sink*) &dest, (controller*) &ctl);

    char* buf = malloc(row_size);
    if(!buf)
    {
        EXCEPTION_THROW_NOMSG(errno);
        HANDLE_EXCEPTION(cleanup_dest);
    }

    do
    {
        sink_read_set(buf, 1, row_size, &dest);
        HANDLE_EXCEPTION(cleanup_buf);
        controller_finalize((controller*) &ctl);
        HANDLE_EXCEPTION(cleanup_buf);
        if(sink_read_get_result(&dest) != row_size)
        {
            break;
        }
        size_t ref;
        memcpy(&ref, buf + hsize + index->name_size, sizeof(ref));
        struct file_info* info =
                file_index_insert_prepared((unsigned char*) buf, (unsigned char*) buf + hsize, index);
        HANDLE_EXCEPTION(cleanup_buf);
        info->ref_count = ref;
    } while(controller_get_stage((controller*) &ctl) != controller_stage_done);

    assert(controller_get_stage((controller*) &ctl) == controller_stage_done);

    cleanup_buf:
    free(buf);
    cleanup_dest:
    sink_destructor((sink*) &dest);
    cleanup_src:
    source_destructor((source*) &src);
    cleanup_ctl:
    ftransform_extract_ctl_destructor(&ctl);
    cleanup_exit:
    ((void)(0));
}

void file_index_open(const struct config* conf, const ftransform_ctx* ctx, struct file_index* index)
{
    assert(conf);
    assert(index);

    file_index_construct(conf, ctx, index);
    HANDLE_EXCEPTION(cleanup_exit);

    file_index_read(index);
    HANDLE_EXCEPTION(cleanup_index);

    return;

    cleanup_index:
    file_index_destroy(index);
    cleanup_exit:
    ((void)(0));
}

static void file_index_write(struct file_index* index)
{
    size_t hsize = file_hash_size(index->conf);
    HANDLE_EXCEPTION(cleanup_exit);

    ftransform_store_ctl ctl;
    ftransform_store_ctl_constructor(index->ctx, &ctl);
    HANDLE_EXCEPTION(cleanup_exit);

    source_write src;

    source_write_constructor(&src);
    HANDLE_EXCEPTION(cleanup_ctl);

    sink_file dest;

    sink_file_constructor(&dest);
    HANDLE_EXCEPTION(cleanup_src);

    sink_file_open(index->path, &dest);
    HANDLE_EXCEPTION(cleanup_dest);

    controller_set_source((source*) &src, (controller*) &ctl);
    controller_set_sink((sink*) &dest, (controller*) &ctl);

    for (struct file_index_value_by_name *val = index->by_name; val != NULL; val = val->hh.next)
    {
        if(val->value->ref_count > 0)
        {
            source_write_set(val->value->hash, 1, hsize, &src);
            HANDLE_EXCEPTION(cleanup_dest);

            controller_work((controller*) &ctl);
            HANDLE_EXCEPTION(cleanup_dest);

            source_write_set(val->value->name, 1, index->name_size, &src);
            HANDLE_EXCEPTION(cleanup_dest);

            controller_work((controller*) &ctl);
            HANDLE_EXCEPTION(cleanup_dest);

            source_write_set(&val->value->ref_count, sizeof(val->value->ref_count), 1, &src);
            HANDLE_EXCEPTION(cleanup_dest);

            controller_work((controller*) &ctl);
            HANDLE_EXCEPTION(cleanup_dest);
        }
    }

    source_write_set(NULL, 1, 0, &src);
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

static void file_index_allocate_files(struct file_index* index)
{
    size_t dir_path_len = strlen(index->file_dir);
    char* name = malloc(FILENAME_MAX + dir_path_len + 2);
    if(!name)
    {
        EXCEPTION_THROW_NOMSG(errno);
        return;
    }
    strcpy(name, index->file_dir);
    strcat(name, "/");
    for (struct file_index_value_by_name *val = index->by_name; val != NULL; val = val->hh.next)
    {
        name[dir_path_len + 1] = '\0';
        strcat(name, val->name);
        if (access(name, F_OK) >= 0)
        {
            if (val->value->ref_count == 0)
            {
                unlink(name);
            }
        }
        else if (errno == ENOENT)
        {
            if (val->value->ref_count > 0)
            {
                FILE *f = fopen(name, "w");
                if (f)
                {
                    fclose(f);
                }
            }
        }
    }
    free(name);
}

void file_index_save(struct file_index* index)
{
    const char* storage = ".~file_index";
    store_file(storage, index->path);
    if(EXCEPTION_IS_THROWN)
    {
        return;
    }

    file_index_write(index);
    if(EXCEPTION_IS_THROWN)
    {
        restore_file(storage, index->path);
        return;
    }
    reset_storage(storage);
    file_index_allocate_files(index);
    if(EXCEPTION_IS_THROWN)
    {
        //This step is optional
        //If it fails, garbage will be left but nothing will break
        //But it's VERY unlikely to fail
        EXCEPTION_CLEAR();
    }
}

void file_index_destroy(struct file_index* index)
{
    assert(index);

    {
        struct file_index_value_by_name *val, *tmp;
        HASH_ITER(hh, index->by_name, val, tmp)
        {
            HASH_DEL(index->by_name, val);
            free(val->name);
            free(val);
        }
    }
    {
        struct file_index_value_by_hash *val, *tmp;
        HASH_ITER(hh, index->by_hash, val, tmp)
        {
            HASH_DEL(index->by_hash, val);
            free(val->value->hash);
            free(val->value->name);
            free(val->value);
            free(val->hash);
            free(val);
        }
    }
    index->path = NULL;
}

struct file_info* file_index_find_by_hash(const unsigned char *hash, const struct file_index *index)
{
    assert(hash);
    assert(index);

    size_t hsize = file_hash_size(index->conf);
    if(EXCEPTION_IS_THROWN)
    {
        return NULL;
    }

    char* hash_encoded = malloc(file_get_name_length(hsize));
    if(!hash_encoded)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        return NULL;
    }

    file_get_name(hash, hsize, hash_encoded);
    if(EXCEPTION_IS_THROWN)
    {
        free(hash_encoded);
        return NULL;
    }

    struct file_index_value_by_hash* val = NULL;
    HASH_FIND_STR(index->by_hash, hash_encoded, val);
    free(hash_encoded);
    if (val==NULL) {
        return NULL;
    }
    return val->value;
}

struct file_info* file_index_find_by_name(const unsigned char *name, const struct file_index *index)
{
    assert(name);
    assert(index);

    char* name_encoded = malloc(file_get_name_length(index->name_size));
    if(!name_encoded)
    {
        EXCEPTION_THROW_NOMSG(ENOMEM);
        return NULL;
    }
    file_get_name(name, index->name_size, name_encoded);
    if(EXCEPTION_IS_THROWN)
    {
        free(name_encoded);
        return NULL;
    }

    struct file_index_value_by_name* val = NULL;
    HASH_FIND_STR(index->by_name, name_encoded, val);
    free(name_encoded);
    if (val==NULL) {
        return NULL;
    }
    return val->value;
}

struct file_info* file_index_insert(const unsigned char* hash, struct file_index* index)
{
    assert(hash);
    assert(index);

    unsigned char* name = gen_unique_name(index);
    if(EXCEPTION_IS_THROWN)
    {
        return NULL;
    }
    struct file_info* ret = file_index_insert_prepared(hash, name, index);
    free(name);
    return ret;
}

size_t file_index_hash_size(const struct file_index* index)
{
    return file_hash_size(index->conf);
}

const struct config* file_index_config(const struct file_index* index)
{
    return index->conf;
}

const char* file_index_file_dir(const struct file_index* index)
{
    return index->file_dir;
}

size_t file_index_name_size(struct file_index* index)
{
    return index->name_size;
}

extern void file_info_add_ref(struct file_info* file)
{
    ++file->ref_count;
}

extern void file_info_remove_ref(struct file_info* file)
{
    --file->ref_count;
}

extern const unsigned char *file_info_get_hash(struct file_info *file)
{
    return file->hash;
}

extern const unsigned char *file_info_get_name(struct file_info *file)
{
    return file->name;
}

extern size_t file_info_get_ref(struct file_info *file)
{
    return file->ref_count;
}
