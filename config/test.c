#include "config.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>

int main()
{
    struct config conf;
    if(init_config("myconf", &conf) != ERROR_SUCCESS)
    {
        abort();
    }
    set_config_value("testkey", "testval", &conf);
    set_config_value("1", "2", &conf);
    set_config_value("3", "4", &conf);
    set_config_value("1", "5", &conf);
    const char* val = get_config_value("testkey", &conf);
    if(val == NULL)
    {
        abort();
    }
    if(strcmp(val, "testval") != 0)
    {
        abort();
    }
    if(save_config(&conf) != ERROR_SUCCESS)
    {
        abort();
    }
    if(destroy_config(&conf) != ERROR_SUCCESS)
    {
        abort();
    }
    if(load_config("myconf", &conf) != ERROR_SUCCESS)
    {
        abort();
    }
    val = get_config_value("testkey", &conf);
    if(val == NULL)
    {
        abort();
    }
    if(strcmp(val, "testval") != 0)
    {
        abort();
    }
    val = get_config_value("1", &conf);
    if(val == NULL)
    {
        abort();
    }
    if(strcmp(val, "5") != 0)
    {
        abort();
    }
    val = get_config_value("3", &conf);
    if(val == NULL)
    {
        abort();
    }
    if(strcmp(val, "4") != 0)
    {
        abort();
    }
    val = get_config_value("2", &conf);
    if(val != NULL)
    {
        abort();
    }
    set_config_value("2", "6", &conf);
    save_config(&conf);
    destroy_config(&conf);
    if(load_config("myconf", &conf) != ERROR_SUCCESS)
    {
        abort();
    }
    val = get_config_value("testkey", &conf);
    if(val == NULL)
    {
        abort();
    }
    if(strcmp(val, "testval") != 0)
    {
        abort();
    }
    val = get_config_value("1", &conf);
    if(val == NULL)
    {
        abort();
    }
    if(strcmp(val, "5") != 0)
    {
        abort();
    }
    val = get_config_value("3", &conf);
    if(val == NULL)
    {
        abort();
    }
    if(strcmp(val, "4") != 0)
    {
        abort();
    }
    val = get_config_value("2", &conf);
    if(val == NULL)
    {
        abort();
    }
    if(strcmp(val, "6") != 0)
    {
        abort();
    }
    destroy_config(&conf);
    return 0;
}
