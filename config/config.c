#include "config.h"

struct config_key_value
{
    char* key;
    char* value;
};

int init_config(const char* path, struct config* conf);

int load_config(const char* path, struct config* conf);

int save_config(struct config* conf);

extern int destroy_config(struct config* conf);

void set_config_value(const char* key, const char* value, struct config* conf);

const char* get_config_value(const char* key, const struct config* conf);
