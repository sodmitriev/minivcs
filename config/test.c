#include <CTransform/CEasyException/exception.h>
#include "config.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define CHECK(x)\
{\
    if(!(x))\
        abort();\
} ((void)(0))

#define HANDLE_EXCEPTION()                                          \
if(EXCEPTION_IS_THROWN)                                             \
{                                                                   \
    fprintf(stderr, "%d : %s\n", EXCEPTION_ERROR, EXCEPTION_MSG);   \
    abort();                                                        \
} ((void)(0))

int main()
{
    EXCEPTION_CLEAR();
    
    struct config conf;
    config_init("myconf", &conf);
    HANDLE_EXCEPTION();
    config_set("testkey", "testval", &conf);
    HANDLE_EXCEPTION();
    config_set("1", "2", &conf);
    HANDLE_EXCEPTION();
    config_set("3", "4", &conf);
    HANDLE_EXCEPTION();
    config_set("1", "5", &conf);
    HANDLE_EXCEPTION();
    const char* val = config_get("testkey", &conf);
    CHECK(val);
    CHECK(strcmp(val, "testval") == 0);
    config_save(&conf);
    HANDLE_EXCEPTION();
    config_destroy(&conf);
    HANDLE_EXCEPTION();
    config_load("myconf", &conf);
    HANDLE_EXCEPTION();
    val = config_get("testkey", &conf);
    CHECK(val);
    CHECK(strcmp(val, "testval") == 0);
    val = config_get("1", &conf);
    CHECK(val);
    CHECK(strcmp(val, "5") == 0);
    val = config_get("3", &conf);
    CHECK(val);
    CHECK(strcmp(val, "4") == 0);
    val = config_get("2", &conf);
    CHECK(!val);
    config_set("2", "6", &conf);
    HANDLE_EXCEPTION();
    config_save(&conf);
    HANDLE_EXCEPTION();
    config_destroy(&conf);
    HANDLE_EXCEPTION();
    config_load("myconf", &conf);
    HANDLE_EXCEPTION();
    val = config_get("testkey", &conf);
    CHECK(val);
    CHECK(strcmp(val, "testval") == 0);
    val = config_get("1", &conf);
    CHECK(val);
    CHECK(strcmp(val, "5") == 0);
    val = config_get("3", &conf);
    CHECK(val);
    CHECK(strcmp(val, "4") == 0);
    val = config_get("2", &conf);
    CHECK(val);
    CHECK(strcmp(val, "6") == 0);
    config_destroy(&conf);
    HANDLE_EXCEPTION();
    return 0;
}
