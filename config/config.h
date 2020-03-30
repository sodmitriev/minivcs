#ifndef MINIVCS_CONFIG_H
#define MINIVCS_CONFIG_H

#include <stdio.h>

struct config_key_value;

struct config
{
    FILE* file;
    struct config_key_value* hmap;
};

extern void config_init(const char* path, struct config* conf);

extern void config_load(const char* path, struct config* conf);

extern void config_save(struct config* conf);

extern void config_destroy(struct config* conf);



extern void config_set(const char* key, const char* value, struct config* conf);

extern const char* config_get(const char* key, const struct config* conf);



extern void config_print(FILE* out, struct config* conf);

#endif //MINIVCS_CONFIG_H
