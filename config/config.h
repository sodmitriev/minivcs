#ifndef MINIVCS_CONFIG_H
#define MINIVCS_CONFIG_H

#include <ec.h>
#include <stdio.h>

struct config_key_value;

struct config
{
    FILE* file;
    struct config_key_value* hmap;
};

extern int init_config(const char* path, struct config* conf);

extern int load_config(const char* path, struct config* conf);

extern int save_config(struct config* conf);

extern int destroy_config(struct config* conf);



extern int set_config_value(const char* key, const char* value, struct config* conf);

extern const char* get_config_value(const char* key, const struct config* conf);

#endif //MINIVCS_CONFIG_H
