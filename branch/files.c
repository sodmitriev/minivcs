#include "files.h"
#include <file/hash.h>
#include <ec.h>
#include <uthash.h>
#include <assert.h>
#include <file/encode.h>
#include <limits.h>
#include <sys/random.h>
#include "cp.h"

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

static void to_file_name(char* name)
{
    for(char* replace = strchr(name, '/'); replace != NULL; replace = strchr(replace + 1, '/'))
    {
        *replace = '_';
    }
}

extern int file_name_readable(const unsigned char* name, size_t size, char** readable)
{
    int err;
    ENCODE(name, size, err);
    if(err != ERROR_SUCCESS)
    {
        return err;
    }
    to_file_name(name_encoded);
    *readable = name_encoded;
    return ERROR_SUCCESS;
}

static int gen_unique_name(const struct file_index* index, unsigned char** name)
{
    *name = malloc(index->name_size);
    if(!*name)
    {
        return ERROR_SYSTEM;
    }
    int err;
    do
    {
        if (getrandom(*name, index->name_size, 0) != index->name_size)
        {
            free(*name);
            return ERROR_SYSTEM;
        }
    } while((err = file_index_find_by_name(*name, index, NULL)) == ERROR_SUCCESS);
    if(err != ERROR_NOTFOUND)
    {
        free(*name);
        return err;
    }
    return ERROR_SUCCESS;
}

static int file_index_init_mode(const struct config* conf, struct file_index* index, const char* mode)
{
    assert(conf);
    assert(index);
    const char* path = config_get("file_index_path", conf);
    const char* digest = config_get("file_digest", conf);
    const char* name_len_str = config_get("file_name_len", conf);
    if(!path || !digest || !name_len_str)
    {
        return ERROR_CONFIG;
    }

    char* eptr;
    index->name_size = strtoul(name_len_str, &eptr, 10);
    if(eptr == name_len_str || index->name_size > NAME_MAX)
    {
        return ERROR_CONFIG;
    }

    int err = hash_size(digest, &index->hash_size);
    if(err != ERROR_SUCCESS)
    {
        return err;
    }
    FILE* file = fopen(path, mode);
    if(!file)
    {
        return ERROR_SYSTEM;
    }
    index->file = file;
    index->by_hash = NULL;
    index->by_name = NULL;
    index->path = path;
    return ERROR_SUCCESS;
}

static int file_index_insert_prepared(const unsigned char* hash, const unsigned char* name, struct file_index* index, struct file_info** file)
{
    assert(hash);
    assert(name);
    assert(index);

    int err;
    ENCODE(hash, index->hash_size, err);
    if(err != ERROR_SUCCESS)
    {
        return err;
    }

    char* name_encoded;
    err = file_name_readable(name, index->name_size, &name_encoded);
    if(err != ERROR_SUCCESS)
    {
        free(hash_encoded);
        return err;
    }

    struct file_info* info = malloc(sizeof(struct file_info));
    if(!info)
    {
        free(hash_encoded);
        free(name_encoded);
        return ERROR_SYSTEM;
    }

    info->hash = malloc(index->hash_size);
    if(!info->hash)
    {
        free(hash_encoded);
        free(name_encoded);
        free(info);
        return ERROR_SYSTEM;
    }
    memcpy(info->hash, hash, index->hash_size);

    info->name = malloc(index->name_size);
    if(!info->name)
    {
        free(hash_encoded);
        free(name_encoded);
        free(info->hash);
        free(info);
        return ERROR_SYSTEM;
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
        free(hash_encoded);
        free(name_encoded);
        free(info->hash);
        free(info->name);
        free(info);
        return ERROR_SYSTEM;
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
        free(hash_encoded);
        free(name_encoded);
        free(info->hash);
        free(info->name);
        free(info);
        free(by_hash);
        return ERROR_SYSTEM;
    }
    by_name->name = name_encoded;
    by_name->value = info;

    HASH_ADD_STR(index->by_hash, hash, by_hash );
    HASH_ADD_STR(index->by_name, name, by_name );
    if(file)
    {
        *file = info;
    }

    return ERROR_SUCCESS;
}

int file_index_init(const struct config* conf, struct file_index* index)
{
    return file_index_init_mode(conf, index, "w");
}

int file_index_open(const struct config* conf, struct file_index* index)
{
    assert(conf);
    assert(index);
    int err = file_index_init_mode(conf, index, "r+");
    if(err != ERROR_SUCCESS)
    {
        return err;
    }
    const size_t row_size = index->hash_size + index->name_size + sizeof(((struct file_info*)(0))->ref_count);
    unsigned char* buf = malloc(row_size);
    if(!buf)
    {
        file_index_destroy(index);
        return ERROR_SYSTEM;
    }
    while(fread(buf, 1, row_size, index->file) == row_size)
    {
        size_t ref;
        memcpy(&ref, buf + index->hash_size + index->name_size, sizeof(ref));
        struct file_info* info;
        err = file_index_insert_prepared(buf, buf + index->hash_size, index, &info);
        if(err != ERROR_SUCCESS)
        {
            file_index_destroy(index);
            free(buf);
            return err;
        }
        info->ref_count = ref;
    }
    free(buf);
    if(ferror(index->file))
    {
        file_index_destroy(index);
        return ERROR_SYSTEM;
    }
    return ERROR_SUCCESS;
}

static int store_file(const char* storage, const char* path)
{
    if(cp(storage, path) == -1)
    {
        return ERROR_SYSTEM;
    }
    return ERROR_SUCCESS;
}

static int restore_file(const char* storage, const char* path)
{
    if(rename(storage, path) == 0)
    {
        return ERROR_SUCCESS;
    }
    if(cp(path, storage) == -1)
    {
        return ERROR_SYSTEM;
    }
    return ERROR_SUCCESS;
}

static int reset_storage(const char* storage)
{
    if(unlink(storage) < 0)
    {
        return ERROR_SYSTEM;
    }
    return ERROR_SUCCESS;
}

int file_index_save(struct file_index* index)
{
    assert(index);
    assert(index->file);
    const char* storage = ".~file_index";
    int err;

    if (fseek(index->file, 0, SEEK_SET) < 0)
    {
        return ERROR_SYSTEM;
    }

    if((err = store_file(storage, index->path)) != ERROR_SUCCESS)
    {
        return err;
    }

    if (truncate(index->path, 0) < 0)
    {
        int tmperrno = errno;
        restore_file(storage, index->path);
        errno = tmperrno;
        return ERROR_SYSTEM;
    }

    struct file_index_value_by_name *val;
    for (val = index->by_name; val != NULL; val = val->hh.next)
    {
        if(val->value->ref_count > 0)
        {
            if (fwrite(val->value->hash, 1, index->hash_size, index->file) != index->hash_size)
            {
                int tmperrno = errno;
                restore_file(storage, index->path);
                errno = tmperrno;
                return ERROR_SYSTEM;
            }
            if (fwrite(val->value->name, 1, index->name_size, index->file) != index->name_size)
            {
                int tmperrno = errno;
                restore_file(storage, index->path);
                errno = tmperrno;
                return ERROR_SYSTEM;
            }
            if (fwrite(&val->value->ref_count, sizeof(val->value->ref_count), 1, index->file) != 1)
            {
                int tmperrno = errno;
                restore_file(storage, index->path);
                errno = tmperrno;
                return ERROR_SYSTEM;
            }
        }
    }
    if(fflush(index->file) < 0)
    {
        int tmperrno = errno;
        restore_file(storage, index->path);
        errno = tmperrno;
        return ERROR_SYSTEM;
    }
    reset_storage(storage);
    for (val = index->by_name; val != NULL; val = val->hh.next)
    {
        if(access(val->name, F_OK) >= 0)
        {
            if(val->value->ref_count == 0)
            {
                unlink(val->name);
            }
        }
        else if(errno == ENOENT)
        {
            if(val->value->ref_count > 0)
            {
                FILE* f = fopen(val->name, "w");
                if(f)
                {
                    fclose(f);
                }
            }
        }
    }
    return ERROR_SUCCESS;
}

int file_index_destroy(struct file_index* index)
{
    assert(index);
    assert(index->file);

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
    if(fclose(index->file) < 0)
    {
        return ERROR_SYSTEM;
    }
    index->file = NULL;
    return ERROR_SUCCESS;
}

int file_index_find_by_hash(const unsigned char *hash, const struct file_index *index, struct file_info **info)
{
    assert(hash);
    assert(index);

    int err;
    ENCODE(hash, index->hash_size, err);
    if(err != ERROR_SUCCESS)
    {
        return err;
    }

    struct file_index_value_by_hash* val = NULL;
    HASH_FIND_STR(index->by_hash, hash_encoded, val);
    free(hash_encoded);
    if (val==NULL) {
        return ERROR_NOTFOUND;
    }
    if(info)
    {
        *info = val->value;
    }
    return ERROR_SUCCESS;
}

int file_index_find_by_name(const unsigned char *name, const struct file_index *index, struct file_info **info)
{
    assert(name);
    assert(index);

    int err;
    ENCODE(name, index->name_size, err);
    if(err != ERROR_SUCCESS)
    {
        return err;
    }
    to_file_name(name_encoded);

    struct file_index_value_by_name* val = NULL;
    HASH_FIND_STR(index->by_name, name_encoded, val);
    free(name_encoded);
    if (val==NULL) {
        return ERROR_NOTFOUND;
    }
    if(info)
    {
        *info = val->value;
    }
    return ERROR_SUCCESS;
}

int file_index_insert(const unsigned char* hash, struct file_index* index, struct file_info** file)
{
    assert(hash);
    assert(index);

    unsigned char* name;
    int err = gen_unique_name(index, &name);
    if(err != ERROR_SUCCESS)
    {
        return err;
    }
    err = file_index_insert_prepared(hash, name, index, file);
    free(name);
    return err;
}

extern size_t file_index_hash_size(struct file_index* index)
{
    return index->hash_size;
}

extern size_t file_index_name_size(struct file_index* index)
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
