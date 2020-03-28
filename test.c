#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <CTransform/CEasyException/exception.h>
#include <assert.h>
#include "minivcs.h"

const char text[] = "12345678";

int main()
{
    EXCEPTION_CLEAR();
    struct minivcs_project proj;
    struct branch_info;
//    mkdir("project", S_IRWXU | S_IRWXG | S_IRWXO);
//    minivcs_init_default("project", &proj);
//    assert(!EXCEPTION_IS_THROWN);


//    minivcs_init_from_config("project/config", &proj);
//    assert(!EXCEPTION_IS_THROWN);
//    minivcs_open("project/config", &proj);
//    assert(!EXCEPTION_IS_THROWN);
//    minivcs_new_branch("datascience", &proj);
//    assert(!EXCEPTION_IS_THROWN);
//    minivcs_update("datascience", "/home/svuatoslav/datascience", &proj);
//    assert(!EXCEPTION_IS_THROWN);
//    minivcs_extract("datascience", "./datascience", &proj);
//    assert(!EXCEPTION_IS_THROWN);
//    minivcs_delete_branch("datascience", &proj);
//    assert(!EXCEPTION_IS_THROWN);
//    minivcs_destroy(&proj);
//    assert(!EXCEPTION_IS_THROWN);
    return 0;
}
