#include "name.h"
#include <string.h>
#include <file/encode.h>

static void to_file_name(char* name)
{
    for(char* replace = strchr(name, '/'); replace != NULL; replace = strchr(replace + 1, '/'))
    {
        *replace = '_';
    }
}

int file_name_readable(const unsigned char* name, size_t size, char** readable)
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
