#include "files.h"
#include "branch.h"
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <malloc.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <dirent.h>
#include <file/operations.h>

#define DIGEST "sha1"
#define FILE_DIR "./files"
#define BRANCH_DIR "./files"

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

size_t file_count(char *dirname)
{
    int n = 0;
    struct dirent *d;
    DIR *dir = opendir(dirname);
    if (dir == NULL)
        return 0;
    while ((d = readdir(dir)) != NULL) {
        ++n;
    }
    closedir(dir);
    return n;
}

int is_directory_empty(char *dirname) {
    int n = 0;
    struct dirent *d;
    DIR *dir = opendir(dirname);
    if (dir == NULL)
        return 1;
    while ((d = readdir(dir)) != NULL) {
        if(++n > 2)
            break;
    }
    closedir(dir);
    if (n <= 2)
        return 1;
    else
        return 0;
}

int main()
{
    ftransform_ctx ctx = {NULL, NULL, NULL, 0};
    EXCEPTION_CLEAR();
    //File index test
    {
        struct config conf;
        config_init("conf", &conf);
        config_set("file_index_path", "index", &conf);
        config_set("file_dir", FILE_DIR, &conf);
        config_set("file_digest", DIGEST, &conf);
        config_set("file_name_len", "32", &conf);

        mkdir(FILE_DIR, S_IRWXU | S_IRWXG | S_IRWXO);

        struct file_index index;
        file_index_init(&conf, &index);
        HANDLE_EXCEPTION();

        FILE *f = fopen("tmp1", "w");
        fprintf(f, "message1");
        fclose(f);
        f = fopen("tmp2", "w");
        fprintf(f, "message2");
        fclose(f);
        f = fopen("tmp3", "w");
        fprintf(f, "message3");
        fclose(f);

        size_t size = file_hash_size(&conf);
        HANDLE_EXCEPTION();
        assert(size == file_index_hash_size(&index));
        size_t name_size = file_index_name_size(&index);

        unsigned char hash1[size];
        unsigned char hash2[size];
        unsigned char hash3[size];

        file_hash("tmp1", &conf, hash1);
        HANDLE_EXCEPTION();
        file_hash("tmp2", &conf, hash2);
        HANDLE_EXCEPTION();
        file_hash("tmp3", &conf, hash3);
        HANDLE_EXCEPTION();

        struct file_info *info1 = file_index_insert(hash1, &index);
        HANDLE_EXCEPTION();
        assert(memcmp(file_info_get_hash(info1), hash1, size) == 0);
        assert(file_info_get_name(info1));
        assert(file_info_get_ref(info1) == 0);

        struct file_info *info2 = file_index_insert(hash2, &index);
        HANDLE_EXCEPTION();
        assert(memcmp(file_info_get_hash(info2), hash2, size) == 0);
        assert(file_info_get_name(info2));
        assert(file_info_get_ref(info2) == 0);

        struct file_info *info3 = file_index_insert(hash3, &index);
        HANDLE_EXCEPTION();
        assert(memcmp(file_info_get_hash(info3), hash3, size) == 0);
        assert(file_info_get_name(info3));
        assert(file_info_get_ref(info3) == 0);

        assert(memcmp(file_info_get_name(info1), file_info_get_name(info2), name_size) != 0);
        assert(memcmp(file_info_get_name(info1), file_info_get_name(info3), name_size) != 0);
        assert(memcmp(file_info_get_name(info2), file_info_get_name(info3), name_size) != 0);

        struct file_info *found = NULL;

        found = file_index_find_by_hash(hash1, &index);
        HANDLE_EXCEPTION();
        assert(found == info1);

        found = file_index_find_by_hash(hash2, &index);
        HANDLE_EXCEPTION();
        assert(found == info2);

        found = file_index_find_by_hash(hash3, &index);
        HANDLE_EXCEPTION();
        assert(found == info3);

        file_index_save(&index);
        HANDLE_EXCEPTION();

        struct file_index new_index;
        file_index_open(&conf, &new_index);
        HANDLE_EXCEPTION();
        assert(file_index_find_by_hash(hash1, &new_index) == NULL);
        HANDLE_EXCEPTION();
        assert(file_index_find_by_hash(hash2, &new_index) == NULL);
        HANDLE_EXCEPTION();
        assert(file_index_find_by_hash(hash3, &new_index) == NULL);
        HANDLE_EXCEPTION();
        file_index_destroy(&new_index);
        HANDLE_EXCEPTION();

        char *name1_rel = malloc(file_get_name_length(name_size));
        char *name2_rel = malloc(file_get_name_length(name_size));
        char *name3_rel = malloc(file_get_name_length(name_size));

        assert(name1_rel);
        assert(name2_rel);
        assert(name3_rel);

        file_get_name(file_info_get_name(info1), name_size, name1_rel);
        HANDLE_EXCEPTION();
        file_get_name(file_info_get_name(info2), name_size, name2_rel);
        HANDLE_EXCEPTION();
        file_get_name(file_info_get_name(info3), name_size, name3_rel);
        HANDLE_EXCEPTION();

        char *name1 = malloc(strlen(name1_rel) + strlen(FILE_DIR) + 2);
        strcat(strcat(strcpy(name1, FILE_DIR), "/"), name1_rel);
        char *name2 = malloc(strlen(name2_rel) + strlen(FILE_DIR) + 2);
        strcat(strcat(strcpy(name2, FILE_DIR), "/"), name2_rel);
        char *name3 = malloc(strlen(name3_rel) + strlen(FILE_DIR) + 2);
        strcat(strcat(strcpy(name3, FILE_DIR), "/"), name3_rel);

        assert(access(name1, F_OK) == -1 && errno == ENOENT);
        assert(access(name2, F_OK) == -1 && errno == ENOENT);
        assert(access(name3, F_OK) == -1 && errno == ENOENT);

        file_info_add_ref(info1);
        file_info_add_ref(info1);
        file_info_add_ref(info2);

        assert(file_info_get_ref(info1) == 2);
        assert(file_info_get_ref(info2) == 1);
        assert(file_info_get_ref(info3) == 0);

        file_index_save(&index);
        HANDLE_EXCEPTION();

        file_index_open(&conf, &new_index);
        HANDLE_EXCEPTION();
        struct file_info *tmp;
        tmp = file_index_find_by_hash(hash1, &new_index);
        HANDLE_EXCEPTION();
        assert(tmp);
        assert(file_info_get_ref(tmp) == 2);
        assert(memcmp(file_info_get_hash(tmp), file_info_get_hash(info1), size) == 0);
        assert(memcmp(file_info_get_name(tmp), file_info_get_name(info1), name_size) == 0);
        tmp = file_index_find_by_hash(hash2, &new_index);
        HANDLE_EXCEPTION();
        assert(tmp);
        assert(file_info_get_ref(tmp) == 1);
        assert(memcmp(file_info_get_hash(tmp), file_info_get_hash(info2), size) == 0);
        assert(memcmp(file_info_get_name(tmp), file_info_get_name(info2), name_size) == 0);
        assert(file_index_find_by_hash(hash3, &new_index) == NULL);
        HANDLE_EXCEPTION();
        file_index_destroy(&new_index);
        HANDLE_EXCEPTION();

        assert(access(name1, F_OK) == 0);
        assert(access(name2, F_OK) == 0);
        assert(access(name3, F_OK) == -1 && errno == ENOENT);


        file_info_remove_ref(info1);
        file_info_remove_ref(info1);
        file_info_remove_ref(info2);

        assert(file_info_get_ref(info1) == 0);
        assert(file_info_get_ref(info2) == 0);
        assert(file_info_get_ref(info3) == 0);

        file_index_save(&index);
        HANDLE_EXCEPTION();

        file_index_open(&conf, &new_index);
        HANDLE_EXCEPTION();
        assert(file_index_find_by_hash(hash1, &new_index) == NULL);
        HANDLE_EXCEPTION();
        assert(file_index_find_by_hash(hash2, &new_index) == NULL);
        HANDLE_EXCEPTION();
        assert(file_index_find_by_hash(hash3, &new_index) == NULL);
        HANDLE_EXCEPTION();
        file_index_destroy(&new_index);
        HANDLE_EXCEPTION();

        assert(access(name1, F_OK) == -1 && errno == ENOENT);
        assert(access(name2, F_OK) == -1 && errno == ENOENT);
        assert(access(name3, F_OK) == -1 && errno == ENOENT);

        file_index_destroy(&index);
        HANDLE_EXCEPTION();
        config_destroy(&conf);
        HANDLE_EXCEPTION();
        rmdir(FILE_DIR);
        unlink("tmp1");
        unlink("tmp2");
        unlink("tmp3");
        unlink("conf");
        unlink("index");
        free(name1_rel);
        free(name2_rel);
        free(name3_rel);
        free(name1);
        free(name2);
        free(name3);
    }
    //Branch index test
    {
        struct config conf;
        config_init("conf", &conf);
        config_set("branch_index_path", "branch_index", &conf);
        config_set("branch_dir", BRANCH_DIR, &conf);
        config_set("branch_digest", DIGEST, &conf);
        config_set("branch_name_len", "32", &conf);
        config_set("file_index_path", "index", &conf);
        config_set("file_dir", FILE_DIR, &conf);
        config_set("file_digest", DIGEST, &conf);
        config_set("file_name_len", "32", &conf);

        mkdir(FILE_DIR, S_IRWXU | S_IRWXG | S_IRWXO);
        mkdir(BRANCH_DIR, S_IRWXU | S_IRWXG | S_IRWXO);

        struct branch_index index;
        struct branch_index check_index;
        branch_index_init(&conf, &ctx, &index);

        branch_index_new_branch("branch1", &index);
        HANDLE_EXCEPTION();
        branch_index_new_branch("branch2", &index);
        HANDLE_EXCEPTION();
        branch_index_new_branch("branch3", &index);
        HANDLE_EXCEPTION();

        const char* file1;
        const char* file2;
        const char* file3;

        file1 = branch_index_find("branch1", &index);
        HANDLE_EXCEPTION();
        file2 = branch_index_find("branch2", &index);
        HANDLE_EXCEPTION();
        file3 = branch_index_find("branch3", &index);
        HANDLE_EXCEPTION();
        assert(file1);
        assert(file2);
        assert(file3);

        branch_index_save(&index);
        HANDLE_EXCEPTION();

        branch_index_open(&conf, &ctx, &check_index);
        HANDLE_EXCEPTION();

        const char* check_file1;
        const char* check_file2;
        const char* check_file3;

        check_file1 = branch_index_find("branch1", &index);
        HANDLE_EXCEPTION();
        check_file2 = branch_index_find("branch2", &index);
        HANDLE_EXCEPTION();
        check_file3 = branch_index_find("branch3", &index);
        HANDLE_EXCEPTION();
        assert(check_file1);
        assert(check_file2);
        assert(check_file3);

        assert(strcmp(file1, check_file1) == 0);
        assert(strcmp(file2, check_file2) == 0);
        assert(strcmp(file3, check_file3) == 0);

        branch_index_destroy(&check_index);
        HANDLE_EXCEPTION();

        branch_index_delete_branch("branch2", &index);
        HANDLE_EXCEPTION();

        branch_index_save(&index);
        HANDLE_EXCEPTION();

        branch_index_open(&conf, &ctx, &check_index);
        HANDLE_EXCEPTION();

        check_file1 = branch_index_find("branch1", &index);
        HANDLE_EXCEPTION();
        check_file2 = branch_index_find("branch2", &index);
        HANDLE_EXCEPTION();
        check_file3 = branch_index_find("branch3", &index);
        HANDLE_EXCEPTION();
        assert(check_file1);
        assert(!check_file2);
        assert(check_file3);

        assert(strcmp(file1, check_file1) == 0);
        assert(strcmp(file3, check_file3) == 0);

        branch_index_destroy(&check_index);
        HANDLE_EXCEPTION();
        branch_index_destroy(&index);
        HANDLE_EXCEPTION();
        config_destroy(&conf);
        HANDLE_EXCEPTION();
        rmdir(FILE_DIR);
        rmdir(BRANCH_DIR);
        unlink("conf");
        unlink("index");
        unlink("branch_index");
    }
    
    //Branch test
    {
        struct config conf;
        config_init("conf", &conf);
        HANDLE_EXCEPTION();
        config_set("branch_index_path", "branch_index", &conf);
        HANDLE_EXCEPTION();
        config_set("branch_dir", BRANCH_DIR, &conf);
        HANDLE_EXCEPTION();
        config_set("branch_digest", DIGEST, &conf);
        HANDLE_EXCEPTION();
        config_set("branch_name_len", "32", &conf);
        HANDLE_EXCEPTION();
        config_set("file_index_path", "index", &conf);
        HANDLE_EXCEPTION();
        config_set("file_dir", FILE_DIR, &conf);
        HANDLE_EXCEPTION();
        config_set("file_digest", DIGEST, &conf);
        HANDLE_EXCEPTION();
        config_set("file_name_len", "32", &conf);
        HANDLE_EXCEPTION();

        mkdir(FILE_DIR, S_IRWXU | S_IRWXG | S_IRWXO);
        mkdir(BRANCH_DIR, S_IRWXU | S_IRWXG | S_IRWXO);

        mkdir("test_in", S_IRWXU | S_IRWXG | S_IRWXO);
        mkdir("test_in/empty", S_IRWXU | S_IRWXG | S_IRWXO);
        mkdir("test_in/filled1", S_IRWXU | S_IRWXG | S_IRWXO);
        mkdir("test_in/filled2", S_IRWXU | S_IRWXG | S_IRWXO);
        system("echo msg1 > test_in/filled1/file1");
        system("echo msg2 > test_in/filled1/file2");
        system("echo msg1 > test_in/filled1/file3");
        mkdir("test_in/filled1/dir1", S_IRWXU | S_IRWXG | S_IRWXO);
        system("echo msg2 > test_in/filled1/dir1/file1");
        system("echo msg2 > test_in/filled1/dir1/file2");
        system("echo msg3 > test_in/filled1/dir1/file3");
        system("echo msg4 > test_in/filled2/file1");
        system("echo msg3 > test_in/filled2/file2");
        system("echo msg2 > test_in/filled2/file3");

        struct branch_index index;
        struct branch_index check_index;
        struct branch_info branch1;
        struct branch_info branch2;
        struct branch_info branch3;
        branch_index_init(&conf, &ctx, &index);
        HANDLE_EXCEPTION();

        branch_index_new_branch("empty", &index);
        HANDLE_EXCEPTION();
        branch_index_new_branch("filled1", &index);
        HANDLE_EXCEPTION();
        branch_index_new_branch("filled2", &index);
        HANDLE_EXCEPTION();

        const char* names[3];
        assert(branch_index_count(&index) == 3);
        HANDLE_EXCEPTION();
        branch_index_get_names(names, &index);
        HANDLE_EXCEPTION();
        assert(strcmp(names[0], "empty") == 0 || strcmp(names[1], "empty") == 0 ||strcmp(names[2], "empty") == 0);
        assert(strcmp(names[0], "filled1") == 0 || strcmp(names[1], "filled1") == 0 ||strcmp(names[2], "filled1") == 0);
        assert(strcmp(names[0], "filled2") == 0 || strcmp(names[1], "filled2") == 0 ||strcmp(names[2], "filled2") == 0);
/*--------------------------------------------------------------------------------------------------------------------*/
        branch_index_get_branch("empty", &index, &branch1);
        HANDLE_EXCEPTION();
        branch_index_get_branch("filled1", &index, &branch2);
        HANDLE_EXCEPTION();
        branch_index_get_branch("filled2", &index, &branch3);
        HANDLE_EXCEPTION();

        branch_extract("test_out/empty", &branch1);
        HANDLE_EXCEPTION();
        branch_extract("test_out/filled1", &branch2);
        HANDLE_EXCEPTION();
        branch_extract("test_out/filled2", &branch3);
        HANDLE_EXCEPTION();

        assert(access("test_out/empty", F_OK) == 0);
        assert(access("test_out/filled1", F_OK) == 0);
        assert(access("test_out/filled2", F_OK) == 0);

        assert(is_directory_empty("test_out/empty"));
        assert(is_directory_empty("test_out/filled1"));
        assert(is_directory_empty("test_out/filled2"));

        system("rm -rf test_out");

        branch_save(&branch1);
        HANDLE_EXCEPTION();
        branch_save(&branch2);
        HANDLE_EXCEPTION();
        //Do not save 3 for testing

        branch_destroy(&branch1);
        HANDLE_EXCEPTION();
        branch_destroy(&branch2);
        HANDLE_EXCEPTION();
        branch_destroy(&branch3);
        HANDLE_EXCEPTION();

        branch_index_save(&index);
        HANDLE_EXCEPTION();

        branch_index_open(&conf, &ctx, &check_index);
        HANDLE_EXCEPTION();
/*--------------------------------------------------------------------------------------------------------------------*/
        branch_index_get_branch("empty", &check_index, &branch1);
        HANDLE_EXCEPTION();
        branch_index_get_branch("filled1", &check_index, &branch2);
        HANDLE_EXCEPTION();
        branch_index_get_branch("filled2", &check_index, &branch3);
        HANDLE_EXCEPTION();

        branch_extract("test_out/empty", &branch1);
        HANDLE_EXCEPTION();
        branch_extract("test_out/filled1", &branch2);
        HANDLE_EXCEPTION();
        branch_extract("test_out/filled2", &branch3);
        HANDLE_EXCEPTION();

        assert(access("test_out/empty", F_OK) == 0);
        assert(access("test_out/filled1", F_OK) == 0);
        assert(access("test_out/filled2", F_OK) == 0);

        assert(is_directory_empty("test_out/empty"));
        assert(is_directory_empty("test_out/filled1"));
        assert(is_directory_empty("test_out/filled2"));

        system("rm -rf test_out");

        branch_update("test_in/empty", &branch1);
        branch_update("test_in/filled1", &branch2);
        branch_update("test_in/filled2", &branch3);

        branch_save(&branch1);
        HANDLE_EXCEPTION();
        branch_save(&branch2);
        HANDLE_EXCEPTION();
        branch_save(&branch3);
        HANDLE_EXCEPTION();

        branch_extract("test_out/empty", &branch1);
        HANDLE_EXCEPTION();
        branch_extract("test_out/filled1", &branch2);
        HANDLE_EXCEPTION();
        branch_extract("test_out/filled2", &branch3);
        HANDLE_EXCEPTION();

        assert(is_directory_empty("test_out/empty"));
        assert(system("diff test_in/filled1/file1 test_out/filled1/file1") == 0);
        assert(system("diff test_in/filled1/file2 test_out/filled1/file2") == 0);
        assert(system("diff test_in/filled1/file3 test_out/filled1/file3") == 0);
        assert(system("diff test_in/filled1/dir1/file1 test_out/filled1/dir1/file1") == 0);
        assert(system("diff test_in/filled1/dir1/file2 test_out/filled1/dir1/file2") == 0);
        assert(system("diff test_in/filled1/dir1/file3 test_out/filled1/dir1/file3") == 0);
        assert(system("diff test_in/filled2/file1 test_out/filled2/file1") == 0);
        assert(system("diff test_in/filled2/file2 test_out/filled2/file2") == 0);
        assert(system("diff test_in/filled2/file3 test_out/filled2/file3") == 0);

        system("rm -rf test_out");

        branch_destroy(&branch1);
        HANDLE_EXCEPTION();
        branch_destroy(&branch2);
        HANDLE_EXCEPTION();
        branch_destroy(&branch3);
        HANDLE_EXCEPTION();
/*--------------------------------------------------------------------------------------------------------------------*/
        branch_index_get_branch("empty", &check_index, &branch1);
        HANDLE_EXCEPTION();
        branch_index_get_branch("filled1", &check_index, &branch2);
        HANDLE_EXCEPTION();
        branch_index_get_branch("filled2", &check_index, &branch3);
        HANDLE_EXCEPTION();

        branch_extract("test_out/empty", &branch1);
        HANDLE_EXCEPTION();
        branch_extract("test_out/filled1", &branch2);
        HANDLE_EXCEPTION();
        branch_extract("test_out/filled2", &branch3);
        HANDLE_EXCEPTION();

        assert(access("test_out/empty", F_OK) == 0);
        assert(access("test_out/filled1", F_OK) == 0);
        assert(access("test_out/filled2", F_OK) == 0);

        assert(is_directory_empty("test_out/empty"));
        assert(system("diff test_in/filled1/file1 test_out/filled1/file1") == 0);
        assert(system("diff test_in/filled1/file2 test_out/filled1/file2") == 0);
        assert(system("diff test_in/filled1/file3 test_out/filled1/file3") == 0);
        assert(system("diff test_in/filled1/dir1/file1 test_out/filled1/dir1/file1") == 0);
        assert(system("diff test_in/filled1/dir1/file2 test_out/filled1/dir1/file2") == 0);
        assert(system("diff test_in/filled1/dir1/file3 test_out/filled1/dir1/file3") == 0);
        assert(system("diff test_in/filled2/file1 test_out/filled2/file1") == 0);
        assert(system("diff test_in/filled2/file2 test_out/filled2/file2") == 0);
        assert(system("diff test_in/filled2/file3 test_out/filled2/file3") == 0);

        system("rm -rf test_out");

        branch_update("test_in/filled2", &branch1);
        HANDLE_EXCEPTION();
        branch_update("test_in/empty", &branch2);
        HANDLE_EXCEPTION();
        branch_update("test_in/filled1", &branch3);
        HANDLE_EXCEPTION();

        branch_save(&branch1);
        HANDLE_EXCEPTION();
        branch_save(&branch2);
        HANDLE_EXCEPTION();
        //Do not save 3 for testing

        branch_extract("test_out/filled2", &branch1);
        HANDLE_EXCEPTION();
        branch_extract("test_out/empty", &branch2);
        HANDLE_EXCEPTION();
        branch_extract("test_out/filled1", &branch3);
        HANDLE_EXCEPTION();

        assert(is_directory_empty("test_out/empty"));
        assert(system("diff test_in/filled2/file1 test_out/filled1/file1") == 0);
        assert(system("diff test_in/filled2/file2 test_out/filled1/file2") == 0);
        assert(system("diff test_in/filled2/file3 test_out/filled1/file3") == 0);
        assert(system("diff test_in/filled2/file1 test_out/filled2/file1") == 0);
        assert(system("diff test_in/filled2/file2 test_out/filled2/file2") == 0);
        assert(system("diff test_in/filled2/file3 test_out/filled2/file3") == 0);

        system("rm -rf test_out");

        branch_destroy(&branch1);
        HANDLE_EXCEPTION();
        branch_destroy(&branch2);
        HANDLE_EXCEPTION();
        branch_destroy(&branch3);
        HANDLE_EXCEPTION();
/*--------------------------------------------------------------------------------------------------------------------*/
        branch_index_get_branch("empty", &check_index, &branch1);
        HANDLE_EXCEPTION();
        branch_index_get_branch("filled1", &check_index, &branch2);
        HANDLE_EXCEPTION();
        branch_index_get_branch("filled2", &check_index, &branch3);
        HANDLE_EXCEPTION();

        branch_extract("test_out/filled2", &branch1);
        HANDLE_EXCEPTION();
        branch_extract("test_out/empty", &branch2);
        HANDLE_EXCEPTION();
        branch_extract("test_out/filled1", &branch3);
        HANDLE_EXCEPTION();

        assert(is_directory_empty("test_out/empty"));
        assert(system("diff test_in/filled2/file1 test_out/filled1/file1") == 0);
        assert(system("diff test_in/filled2/file2 test_out/filled1/file2") == 0);
        assert(system("diff test_in/filled2/file3 test_out/filled1/file3") == 0);
        assert(system("diff test_in/filled2/file1 test_out/filled2/file1") == 0);
        assert(system("diff test_in/filled2/file2 test_out/filled2/file2") == 0);
        assert(system("diff test_in/filled2/file3 test_out/filled2/file3") == 0);

        system("rm -rf test_out");

        branch_update("test_in/empty", &branch1);
        branch_update("test_in/filled1", &branch2);
        branch_update("test_in/filled2", &branch3);

        branch_save(&branch1);
        HANDLE_EXCEPTION();
        branch_save(&branch2);
        HANDLE_EXCEPTION();
        //Do not save 3 for testing

        branch_destroy(&branch1);
        HANDLE_EXCEPTION();
        branch_destroy(&branch2);
        HANDLE_EXCEPTION();
        branch_destroy(&branch3);
        HANDLE_EXCEPTION();

        //Check index has a more recent version of file index, passing &index would lead to corruption
        branch_index_delete_branch("filled1", &check_index);
        HANDLE_EXCEPTION();
        branch_index_save(&check_index);
        HANDLE_EXCEPTION();

        assert(branch_index_count(&check_index) == 2);
        names[0] = NULL;
        names[1] = NULL;
        branch_index_get_names(names, &check_index);
        HANDLE_EXCEPTION();
        assert(strcmp(names[0], "empty") == 0 || strcmp(names[1], "empty") == 0);
        assert(strcmp(names[0], "filled2") == 0 || strcmp(names[1], "filled2") == 0);

        branch_index_destroy(&check_index);
        HANDLE_EXCEPTION();
/*--------------------------------------------------------------------------------------------------------------------*/
        branch_index_open(&conf, &ctx, &check_index);
        HANDLE_EXCEPTION();

        branch_index_get_branch("empty", &check_index, &branch1);
        HANDLE_EXCEPTION();
        branch_index_get_branch("filled1", &check_index, &branch2);
        assert(EXCEPTION_IS_THROWN);
        EXCEPTION_CLEAR();
        branch_index_get_branch("filled2", &check_index, &branch3);
        HANDLE_EXCEPTION();

        branch_destroy(&branch1);
        HANDLE_EXCEPTION();
        branch_destroy(&branch3);
        HANDLE_EXCEPTION();
        branch_index_destroy(&check_index);
        HANDLE_EXCEPTION();
/*--------------------------------------------------------------------------------------------------------------------*/
        branch_index_destroy(&index);
        HANDLE_EXCEPTION();
        config_destroy(&conf);
        HANDLE_EXCEPTION();
        system("rm -rf "FILE_DIR);
        system("rm -rf "BRANCH_DIR);
        system("rm -rf test_in");
        system("rm -rf test_out");
        unlink("conf");
        unlink("index");
        unlink("branch_index");
    }
    return 0;
}
