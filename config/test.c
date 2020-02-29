#include "config.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ec.h>

int main()
{
    struct config conf;
    if(config_init("myconf", &conf) != ERROR_SUCCESS)
    {
        abort();
    }
    config_set("testkey", "testval", &conf);
    config_set("1", "2", &conf);
    config_set("3", "4", &conf);
    config_set("1", "5", &conf);
    const char* val = config_get("testkey", &conf);
    if(val == NULL)
    {
        abort();
    }
    if(strcmp(val, "testval") != 0)
    {
        abort();
    }
    if(config_save(&conf) != ERROR_SUCCESS)
    {
        abort();
    }
    if(config_destroy(&conf) != ERROR_SUCCESS)
    {
        abort();
    }
    if(config_load("myconf", &conf) != ERROR_SUCCESS)
    {
        abort();
    }
    val = config_get("testkey", &conf);
    if(val == NULL)
    {
        abort();
    }
    if(strcmp(val, "testval") != 0)
    {
        abort();
    }
    val = config_get("1", &conf);
    if(val == NULL)
    {
        abort();
    }
    if(strcmp(val, "5") != 0)
    {
        abort();
    }
    val = config_get("3", &conf);
    if(val == NULL)
    {
        abort();
    }
    if(strcmp(val, "4") != 0)
    {
        abort();
    }
    val = config_get("2", &conf);
    if(val != NULL)
    {
        abort();
    }
    config_set("2", "6", &conf);
    config_save(&conf);
    config_destroy(&conf);
    if(config_load("myconf", &conf) != ERROR_SUCCESS)
    {
        abort();
    }
    val = config_get("testkey", &conf);
    if(val == NULL)
    {
        abort();
    }
    if(strcmp(val, "testval") != 0)
    {
        abort();
    }
    val = config_get("1", &conf);
    if(val == NULL)
    {
        abort();
    }
    if(strcmp(val, "5") != 0)
    {
        abort();
    }
    val = config_get("3", &conf);
    if(val == NULL)
    {
        abort();
    }
    if(strcmp(val, "4") != 0)
    {
        abort();
    }
    val = config_get("2", &conf);
    if(val == NULL)
    {
        abort();
    }
    if(strcmp(val, "6") != 0)
    {
        abort();
    }
    config_destroy(&conf);
    return 0;
}
