#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include "minivcs.h"

const char text[] = "12345678";

int main()
{
    struct minivcs_project proj;
    struct branch_info;
//    mkdir("proj", S_IRWXU | S_IRWXG | S_IRWXO);
//    int err = minivcs_init_default("proj", &proj);
    //minivcs_init_from_config("project/config", &proj);
    minivcs_open("project/config", &proj);
    //minivcs_new_branch("datascience", &proj);
    //minivcs_update("datascience", "/home/svuatoslav/datascience", &proj);
    //minivcs_extract("datascience", "./datascience", &proj);
    minivcs_delete_branch("datascience", &proj);
    minivcs_destroy(&proj);
    return 0;
}
