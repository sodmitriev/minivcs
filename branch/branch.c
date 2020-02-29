#include "branch.h"
#include "storage.h"
#include "name.h"
#include <assert.h>
#include <ec.h>
#include <dirent.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <uthash.h>
#include <zconf.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <file/hash.h>

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

static int branch_index_init_mode(const struct config* conf, struct branch_index* index, const char* mode)
{
    assert(conf);
    assert(index);
    const char* path = config_get("branch_index_path", conf);
    const char* branch_dir = config_get("branch_dir", conf);
    const char* digest = config_get("branch_digest", conf);
    const char* name_len_str = config_get("branch_name_len", conf);
    if(!path || !branch_dir || !digest || !name_len_str)
    {
        return ERROR_CONFIG;
    }

    {
        DIR* dir = opendir(branch_dir);
        if(dir == NULL)
        {
            return ERROR_SYSTEM;
        }
        closedir(dir);
    }

    char* eptr;
    index->file_name_size = strtoul(name_len_str, &eptr, 10);
    if(eptr == name_len_str || index->file_name_size > NAME_MAX)
    {
        return ERROR_CONFIG;
    }

    FILE* file = fopen(path, mode);
    if(!file)
    {
        return ERROR_SYSTEM;
    }
    index->file = file;
    index->by_name = NULL;
    index->by_file = NULL;
    index->path = path;
    index->branch_dir = branch_dir;
    //index->files will be initialized later
    return ERROR_SUCCESS;
}

static int branch_index_destroy_nofiles(struct branch_index* branch_index)
{
    assert(branch_index);
    assert(branch_index->file);

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
    if(fclose(branch_index->file) < 0)
    {
        return ERROR_SYSTEM;
    }
    branch_index->file = NULL;
    return ERROR_SUCCESS;
}

static int gen_unique_file(const struct branch_index* index, char** file)
{
    unsigned char* raw_name = malloc(index->file_name_size);
    if(!raw_name)
    {
        return ERROR_SYSTEM;
    }
    int err;
    struct branch_index_value* val;
    do
    {
        if (getrandom(raw_name, index->file_name_size, 0) != index->file_name_size)
        {
            free(raw_name);
            return ERROR_SYSTEM;
        }
        err = file_name_readable(raw_name, index->file_name_size, file);
        if(err != ERROR_SUCCESS)
        {
            free(raw_name);
            return err;
        }
        val = NULL;
        HASH_FIND_STR(index->by_file, *file, val);
        if(val != NULL)
        {
            free(*file);
        }
    } while(val);
    free(raw_name);
    return ERROR_SUCCESS;
}

int branch_index_new_branch_prepared(const char* name, const char* file, struct branch_index* branch_index)
{
    assert(name);
    assert(file);
    assert(branch_index);

    if(strchr(name, ' ') || strchr(name, '\n'))
    {
        return ERROR_FORMAT;
    }

    char* name_dup = strdup(name);
    if(!name_dup)
    {
        return ERROR_SYSTEM;
    }
    char* file_dup = strdup(file);
    if(!file_dup)
    {
        free(name_dup);
        return ERROR_SYSTEM;
    }

    struct branch_index_value* by_name = NULL;
#ifndef NDEBUG
    HASH_FIND_STR(branch_index->by_name, name, by_name);
    assert(by_name == NULL);
#endif
    by_name = malloc(sizeof(struct branch_index_value));
    if(by_name == NULL)
    {
        free(name_dup);
        free(file_dup);
        return ERROR_SYSTEM;
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
        free(name_dup);
        free(file_dup);
        free(by_name);
        return ERROR_SYSTEM;
    }
    by_file->name = name_dup;
    by_file->file = file_dup;
    by_file->deleted = 0;

    HASH_ADD_STR(branch_index->by_name, name, by_name );
    HASH_ADD_STR(branch_index->by_file, file, by_file );

    return ERROR_SUCCESS;
}

int branch_index_init(const struct config* conf, struct branch_index* branch_index)
{
    assert(conf);
    assert(branch_index);
    int err = branch_index_init_mode(conf, branch_index, "w");
    if(err != ERROR_SUCCESS)
    {
        return err;
    }
    err = file_index_init(conf, &branch_index->files);
    if(err != ERROR_SUCCESS)
    {
        int tmperrno = errno;
        branch_index_destroy_nofiles(branch_index);
        errno = tmperrno;
        return err;
    }
    return ERROR_SUCCESS;
}

int branch_index_open(const struct config* conf, struct branch_index* branch_index)
{
    assert(conf);
    assert(branch_index);
    int err = branch_index_init_mode(conf, branch_index, "r+");
    if(err != ERROR_SUCCESS)
    {
        return err;
    }
    err = file_index_open(conf, &branch_index->files);
    if(err != ERROR_SUCCESS)
    {
        int tmperrno = errno;
        branch_index_destroy_nofiles(branch_index);
        errno = tmperrno;
        return err;
    }

    char line[LINE_MAX];
    while (fgets(line, sizeof line, branch_index->file))
    {
        size_t len = strlen(line);
        if (len && (line[len - 1] != '\n'))
        {
            continue;
        }
        char* val_start = strchr(line, ' ');
        if(val_start == NULL)
        {
            continue;
        }
        *val_start = '\0';
        ++val_start;
        if(*val_start == '\0')
        {
            continue;
        }
        char* val_end = strchr(val_start, '\n');
        if(val_end != NULL)
        {
            *val_end = '\0';
        }
        branch_index_new_branch_prepared(line, val_start, branch_index);
    }
    if(ferror(branch_index->file))
    {
        int tmperrno = errno;
        branch_index_destroy(branch_index);
        errno = tmperrno;
        return ERROR_SYSTEM;
    }
    return ERROR_SUCCESS;
}

int branch_index_save(struct branch_index* index)
{
    assert(index);
    assert(index->file);
    const char* storage = ".~branch_index";
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

    struct branch_index_value *val, *tmp;
    for (val = index->by_name; val != NULL; val = val->hh.next)
    {
        if(val->deleted == 0)
        {
            if (fprintf(index->file, "%s %s\n", val->name, val->file) < 0)
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

    char* name = malloc(PATH_MAX + 1);
    if(!name)
    {
        int tmperrno = errno;
        restore_file(storage, index->path);
        errno = tmperrno;
        return ERROR_SYSTEM;
    }
    strcpy(name, index->branch_dir);
    strcat(name, "/");
    char* name_end = strchr(name, '\0');
    assert(name_end);

    HASH_ITER(hh, index->by_name, val, tmp)
    {
        if(val->deleted == 1)
        {
            struct branch_info branch;
            err = branch_index_get_branch(val->name, index, &branch);
            if(err == ERROR_SUCCESS)
            {
                branch.files = NULL;
                err = branch_save(&branch);
                branch_destroy(&branch);
            }

            struct branch_index_value* by_file_val;
            HASH_FIND_STR(index->by_file, val->file, by_file_val);
            assert(by_file_val);
            HASH_DEL(index->by_name, val);
            HASH_DEL(index->by_file, by_file_val);
            if(err == ERROR_SUCCESS)
            {
                strcpy(name_end, val->file);
                unlink(name);
            }
            free(val->file);
            free(val->name);
            free(val);
            free(by_file_val);
        }
    }
    free(name);
    reset_storage(storage);
    return ERROR_SUCCESS;
}

int branch_index_destroy(struct branch_index* index)
{
    int err_branch = branch_index_destroy_nofiles(index);
    int err_files = file_index_destroy(&index->files);
    return err_branch == ERROR_SUCCESS ? err_files : err_branch;
}

int branch_index_new_branch(const char* name, struct branch_index* branch_index)
{
    assert(name);
    assert(branch_index);
    char* file;
    int err = gen_unique_file(branch_index, &file);
    if(err != ERROR_SUCCESS)
    {
        return err;
    }
    err = branch_index_new_branch_prepared(name, file, branch_index);
    free(file);
    return err;
}

int branch_index_delete_branch(const char* name, struct branch_index* branch_index)
{
    struct branch_index_value* val = NULL;
    HASH_FIND_STR(branch_index->by_name, name, val);
    if(!val)
    {
        return ERROR_NOTFOUND;
    }
    val->deleted = 1;
    return ERROR_SUCCESS;
}

int branch_index_find(const char* name, struct branch_index* index, const char** file)
{
    struct branch_index_value* val = NULL;
    HASH_FIND_STR(index->by_name, name, val);
    if(!val)
    {
        return ERROR_NOTFOUND;
    }
    if(file)
    {
        *file = val->file;
    }
    return ERROR_SUCCESS;
}

static int branch_create(struct branch_info* branch)
{
    branch->file = fopen(branch->path, "w");
    if(!branch->file)
    {
        return ERROR_SYSTEM;
    }
    branch->files = NULL;
    branch->files_saved = NULL;
    return ERROR_SUCCESS;
}

static int branch_open(struct branch_info* branch)
{
    size_t hash_size = file_index_hash_size(branch->index);
    unsigned char* hash_buf = malloc(hash_size);
    if(!hash_buf)
    {
        return ERROR_SYSTEM;
    }
    char* path_buf = malloc(PATH_MAX + 1);
    if(!path_buf)
    {
        return ERROR_SYSTEM;
    }
    branch->files = NULL;
    branch->file = fopen(branch->path, "r+");
    if(!branch->file)
    {
        free(hash_buf);
        free(path_buf);
        return ERROR_SYSTEM;
    }
    while(1)
    {
        if(fread(hash_buf, 1, hash_size, branch->file) < hash_size)
        {
            break;
        }
        if(fgets(path_buf, PATH_MAX + 1, branch->file) == NULL)
        {
            break;
        }
        char* nl = strchr(path_buf, '\n');
        if(nl)
        {
            *nl = 0;
        }
        struct branch_info_value* val = malloc(sizeof(struct branch_info_value));
        if(!val)
        {
            branch_destroy(branch);
            free(hash_buf);
            free(path_buf);
            errno = ENOMEM;
            return ERROR_SYSTEM;
        }
        val->hash = malloc(hash_size);
        if(!val->hash)
        {
            branch_destroy(branch);
            free(hash_buf);
            free(path_buf);
            free(val);
            errno = ENOMEM;
            return ERROR_SYSTEM;
        }
        memcpy(val->hash, hash_buf, hash_size);
        val->path = strdup(path_buf);
        if(!val->path)
        {
            branch_destroy(branch);
            free(hash_buf);
            free(path_buf);
            free(val->hash);
            free(val);
            errno = ENOMEM;
            return ERROR_SYSTEM;
        }
        val->next = branch->files;
        branch->files = val;
    }
    free(hash_buf);
    free(path_buf);
    if(ferror(branch->file))
    {
        int tmp = errno;
        branch_destroy(branch);
        errno = tmp;
        return ERROR_SYSTEM;
    }
    branch->files_saved = branch->files;
    return ERROR_SUCCESS;
}

int branch_index_get_branch(const char* name, struct branch_index* index, struct branch_info* branch)
{
    assert(name);
    assert(index);
    assert(branch);
    const char* file = NULL;
    int err = branch_index_find(name, index, &file);
    if(err != ERROR_SUCCESS)
    {
        return err;
    }
    branch->path = malloc(strlen(index->branch_dir) + strlen(file) + 2);
    if(!branch->path)
    {
        return ERROR_SYSTEM;
    }
    strcpy(branch->path, index->branch_dir);
    strcat(branch->path, "/");
    strcat(branch->path, file);
    branch->index = &index->files;
    branch->branch_dir = index->branch_dir;
    branch->imported_dir = NULL;
    struct stat file_stat;
    err = stat(branch->path, &file_stat);
    if(err == 0 && S_ISREG(file_stat.st_mode))
    {
        err = branch_open(branch);
        if(err != ERROR_SUCCESS)
        {
            free(branch->path);
        }
        return err;
    }
    else if(err < 0 && errno == ENOENT)
    {
        err = branch_create(branch);
        if(err != ERROR_SUCCESS)
        {
            free(branch->path);
        }
        return err;
    }
    else if(err == 0)
    {
        free(branch->path);
        return ERROR_FILETYPE;
    }
    else
    {
        free(branch->path);
        return ERROR_SYSTEM;
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

int branch_save(struct branch_info* branch)
{
    assert(branch);
    assert(branch->file);
    if(branch->files_saved == branch->files)
    {
        return ERROR_SUCCESS;
    }
    assert(branch->imported_dir || branch->files == NULL);
    const char* storage = ".~branch";
    int err;

    if (fseek(branch->file, 0, SEEK_SET) < 0)
    {
        return ERROR_SYSTEM;
    }

    if((err = store_file(storage, branch->path)) != ERROR_SUCCESS)
    {
        return err;
    }

    if (truncate(branch->path, 0) < 0)
    {
        int tmperrno = errno;
        restore_file(storage, branch->path);
        errno = tmperrno;
        return ERROR_SYSTEM;
    }
    size_t hash_size = file_index_hash_size(branch->index);
    struct branch_info_value *val;
    for (val = branch->files; val != NULL; val = val->next)
    {
        if (fwrite(val->hash, 1, hash_size, branch->file) != hash_size)
        {
            int tmperrno = errno;
            restore_file(storage, branch->path);
            errno = tmperrno;
            return ERROR_SYSTEM;
        }
        size_t len = strlen(val->path);
        if (fwrite(val->path, 1, len, branch->file) != len)
        {
            int tmperrno = errno;
            restore_file(storage, branch->path);
            errno = tmperrno;
            return ERROR_SYSTEM;
        }
        if (fputc('\n', branch->file) == EOF)
        {
            int tmperrno = errno;
            restore_file(storage, branch->path);
            errno = tmperrno;
            return ERROR_SYSTEM;
        }
    }
    if(fflush(branch->file) < 0)
    {
        int tmperrno = errno;
        restore_file(storage, branch->path);
        errno = tmperrno;
        return ERROR_SYSTEM;
    }
    for (val = branch->files_saved; val != NULL; val = val->next)
    {
        if(val->path[strlen(val->path) - 1] != '/')
        {
            struct file_info *info;
            err = file_index_find_by_hash(val->hash, branch->index, &info);
            if (err == ERROR_NOTFOUND)
            {
                perror("Corrupted data");
                restore_file(storage, branch->path);
                abort();
            }
            else if (err != ERROR_SUCCESS)
            {
                perror("Critical error, aborting to prevent data loss");
                restore_file(storage, branch->path);
                abort();
            }
            file_info_remove_ref(info);
        }
    }
    for (val = branch->files; val != NULL; val = val->next)
    {
        if(val->path[strlen(val->path) - 1] != '/')
        {
            struct file_info *info;
            err = file_index_find_by_hash(val->hash, branch->index, &info);
            if (err == ERROR_SUCCESS)
            {
                file_info_add_ref(info);
            }
            else if (err == ERROR_NOTFOUND)
            {
                if (file_index_insert(val->hash, branch->index, &info) != ERROR_SUCCESS)
                {
                    restore_file(storage, branch->path);
                    perror("Critical error, aborting to prevent data loss");
                    abort();
                }
                file_info_add_ref(info);
                char *fname;
                if (file_name_readable(file_info_get_name(info), file_index_name_size(branch->index), &fname) !=
                    ERROR_SUCCESS)
                {
                    restore_file(storage, branch->path);
                    perror("Critical error, aborting to prevent data loss");
                    abort();
                }
                char *full_path = malloc(strlen(val->path) + 2 + strlen(branch->imported_dir));
                if (!full_path)
                {
                    restore_file(storage, branch->path);
                    perror("Critical error, aborting to prevent data loss");
                    abort();
                }
                char *full_name = malloc(strlen(fname) + 2 + strlen(file_index_file_dir(branch->index)));
                if (!full_name)
                {
                    restore_file(storage, branch->path);
                    perror("Critical error, aborting to prevent data loss");
                    abort();
                }
                strcpy(full_path, branch->imported_dir);
                strcat(full_path, "/");
                strcat(full_path, val->path);
                strcpy(full_name, file_index_file_dir(branch->index));
                strcat(full_name, "/");
                strcat(full_name, fname);
                if (cp(full_name, full_path) < 0)
                {
                    restore_file(storage, branch->path);
                    perror("Critical error, aborting to prevent data loss");
                    abort();
                }
                free(fname);
                free(full_path);
                free(full_name);
            }
            else
            {
                restore_file(storage, branch->path);
                perror("Critical error, aborting to prevent data loss");
                abort();
            }
        }
    }
    if(file_index_save(branch->index) != ERROR_SUCCESS)
    {
        restore_file(storage, branch->path);
        perror("Critical error, aborting to prevent data loss");
        abort();
    }
    reset_storage(storage);
    destroy_list(branch->files_saved);
    branch->files_saved = branch->files;
    return ERROR_SUCCESS;
}

int branch_destroy(struct branch_info* branch)
{
    assert(branch);
    assert(branch->file);
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
    if(fclose(branch->file) < 0)
    {
        return ERROR_SYSTEM;
    }
    branch->file = NULL;
    return ERROR_SUCCESS;
}

static int create_subdirs(char* path)
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

int branch_extract(const struct branch_info* branch, const char* dst_dir)
{
    assert(branch);
    assert(dst_dir);
    size_t to_dir_path_len = strlen(dst_dir);
    size_t from_dir_path_len = strlen(branch->branch_dir);
    if(to_dir_path_len + 2 > PATH_MAX || from_dir_path_len + 2 > PATH_MAX)
    {
        errno = ENAMETOOLONG;
        return ERROR_SYSTEM;
    }
    char* to = malloc(PATH_MAX + 1);
    if(!to)
    {
        return ERROR_SYSTEM;
    }
    char* from = malloc(PATH_MAX + 1);
    if(!from)
    {
        free(to);
        return ERROR_SYSTEM;
    }
    strcpy(to, dst_dir);
    strcat(to, "/");
    strcpy(from, file_index_file_dir(branch->index));
    strcat(from, "/");
    int err = create_subdirs(to);
    if(err != ERROR_SUCCESS)
    {
        free(to);
        free(from);
        return err;
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
            free(to);
            free(from);
            errno = ENAMETOOLONG;
            return ERROR_SYSTEM;
        }
        if(val->path[strlen(val->path) - 1] == '/')
        {
            *to_end = '\0';
            strcat(to_end, val->path);
            err = create_subdirs(to);
            if (err != ERROR_SUCCESS)
            {
                free(to);
                free(from);
                return err;
            }
        }
        else
        {
            struct file_info *info;
            err = file_index_find_by_hash(val->hash, branch->index, &info);
            if (err != ERROR_SUCCESS)
            {
                free(to);
                free(from);
                return err;
            }
            char *orig_name;
            err = file_name_readable(file_info_get_name(info), file_index_name_size(branch->index), &orig_name);
            if (err != ERROR_SUCCESS)
            {
                free(to);
                free(from);
                errno = ENAMETOOLONG;
                return ERROR_SYSTEM;
            }
            if (from_dir_path_len + 1 + strlen(orig_name) > PATH_MAX)
            {
                free(to);
                free(from);
                free(orig_name);
                errno = ENAMETOOLONG;
                return ERROR_SYSTEM;
            }
            *to_end = '\0';
            *from_end = '\0';
            strcat(to_end, val->path);
            strcat(from_end, orig_name);
            free(orig_name);
            err = create_subdirs(to);
            if (err != ERROR_SUCCESS)
            {
                free(to);
                free(from);
                return err;
            }
            if (cp(to, from) < 0)
            {
                free(to);
                free(from);
                return ERROR_SYSTEM;
            }
        }
    }
    free(to);
    free(from);
    return ERROR_SUCCESS;
}

static int branch_put_dir(struct branch_info* branch, struct branch_info_value** htab, char* src_dir, size_t orig_len)
{
    char* dir_end = strchr(src_dir, '\0');
    assert(dir_end);
    DIR *dir = opendir(src_dir);
    size_t hash_size = file_index_hash_size(branch->index);
    if (dir == NULL)
    {
        return ERROR_SYSTEM;
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
            int tmp = errno;
            *dir_end = '\0';
            closedir(dir);
            errno = tmp;
            return ERROR_SYSTEM;
        }
        if(S_ISREG(file_stat.st_mode))
        {
            char* namedup = strdup(src_dir + orig_len + 1);
            if(!namedup)
            {
                int tmp = errno;
                *dir_end = '\0';
                closedir(dir);
                errno = tmp;
                return ERROR_SYSTEM;
            }
            unsigned char* fhash = malloc(hash_size);
            if(!fhash)
            {
                int tmp = errno;
                *dir_end = '\0';
                closedir(dir);
                free(namedup);
                errno = tmp;
                return ERROR_SYSTEM;
            }
            err = hash(src_dir, file_index_hash_digest(branch->index), fhash);
            if(err != ERROR_SUCCESS)
            {
                int tmp = errno;
                *dir_end = '\0';
                closedir(dir);
                free(namedup);
                free(fhash);
                errno = tmp;
                return ERROR_SYSTEM;
            }
            struct branch_info_value* val = malloc(sizeof(struct branch_info_value));
            if(!val)
            {
                int tmp = errno;
                *dir_end = '\0';
                closedir(dir);
                free(namedup);
                free(fhash);
                errno = tmp;
                return ERROR_SYSTEM;
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
            return ERROR_SYSTEM;
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
            return ERROR_SYSTEM;
        }
        memset(fhash, 0, hash_size);
        struct branch_info_value* val = malloc(sizeof(struct branch_info_value));
        if(!val)
        {
            *dir_end = '\0';
            free(namedup);
            free(fhash);
            return ERROR_SYSTEM;
        }
        val->hash = fhash;
        val->path = namedup;
        val->next = *htab;
        *htab = val;
    }
    *dir_end = '\0';
    return ERROR_SUCCESS;
}

int branch_update(struct branch_info* branch, const char* src_dir)
{
    char* impdir = strdup(src_dir);
    if(!impdir)
    {
        return ERROR_SYSTEM;
    }
    char* name = malloc(PATH_MAX + 1);
    if(!name)
    {
        free(impdir);
        return ERROR_SYSTEM;
    }
    strcpy(name, src_dir);
    struct branch_info_value* htab = NULL;
    int err = branch_put_dir(branch, &htab, name, strlen(src_dir));
    free(name);
    if(err != ERROR_SUCCESS)
    {
        free(impdir);
        destroy_list(htab);
        return err;
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
    return ERROR_SUCCESS;
}
