#include "config.h"
#include <uthash.h>
#include <limits.h>
#include <errno.h>

struct config_key_value
{
    char* key;
    char* value;
    UT_hash_handle hh;
};

int init_config(const char* path, struct config* conf)
{
    FILE* file = fopen(path, "w");
    if(file == NULL)
    {
        return ERROR_SYSTEM;
    }
    conf->file = file;
    conf->hmap = NULL;
    return ERROR_SUCCESS;
}

int load_config(const char* path, struct config* conf)
{
    FILE* file = fopen(path, "r+");
    if(file == NULL)
    {
        return ERROR_SYSTEM;
    }
    conf->file = file;
    conf->hmap = NULL;
    char line[LINE_MAX];
    while (fgets(line, sizeof line, file))
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
        set_config_value(line, val_start, conf);
    }
    return ferror(file) == 0 ? ERROR_SUCCESS : ERROR_SYSTEM;
}

int save_config(struct config* conf)
{
    if (fseek(conf->file, 0, SEEK_SET) < 0)
    {
        return ERROR_SYSTEM;
    }
    struct config_key_value *val;
    for (val = conf->hmap; val != NULL; val = val->hh.next)
    {
        if (fprintf(conf->file, "%s %s\n", val->key, val->value) < 0)
        {
            return ERROR_SYSTEM;
        }
    }
    return ERROR_SUCCESS;
}

extern int destroy_config(struct config* conf)
{
    struct config_key_value *val, *tmp;
    HASH_ITER(hh, conf->hmap, val, tmp) {
        HASH_DEL(conf->hmap, val);
        free(val->key);
        free(val->value);
        free(val);
    }
    if(fclose(conf->file) < 0)
    {
        return ERROR_SYSTEM;
    }
    conf->file = NULL;
    return ERROR_SUCCESS;
}

void set_config_value(const char* key, const char* value, struct config* conf)
{
    struct config_key_value* val = NULL;
    HASH_FIND_STR(conf->hmap, key, val);
    if (val==NULL) {
        val = malloc(sizeof(struct config_key_value));
        val->key = strdup(key);
        HASH_ADD_STR( conf->hmap, key, val );
    }
    else
    {
        free(val->value);
    }
    val->value = strdup(value);
}

const char* get_config_value(const char* key, const struct config* conf)
{
    struct config_key_value* val = NULL;
    HASH_FIND_STR(conf->hmap, key, val);
    if (val==NULL) {
        return NULL;
    }
    return val->value;
}
