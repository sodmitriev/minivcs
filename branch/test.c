#include "files.h"
#include <file/hash.h>
#include <ec.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <malloc.h>

#define DIGEST "sha1"

int main()
{
    struct config conf;
    config_init("conf", &conf);
    config_set("file_index_path", "index", &conf);
    config_set("file_digest", DIGEST, &conf);
    config_set("file_name_len", "32", &conf);

    struct file_index index;
    file_index_init(&conf, &index);

    FILE* f = fopen("tmp1", "w");
    fprintf(f, "message1");
    fclose(f);
    f = fopen("tmp2", "w");
    fprintf(f, "message2");
    fclose(f);
    f = fopen("tmp3", "w");
    fprintf(f, "message3");
    fclose(f);

    size_t size;
    hash_size(DIGEST, &size);
    assert(size == file_index_hash_size(&index));
    size_t name_size = file_index_name_size(&index);

    unsigned char hash1[size];
    unsigned char hash2[size];
    unsigned char hash3[size];

    hash("tmp1", DIGEST, hash1);
    hash("tmp2", DIGEST, hash2);
    hash("tmp3", DIGEST, hash3);

    struct file_info* info1;
    file_index_insert(hash1, &index, &info1);
    assert(memcmp(file_info_get_hash(info1), hash1, size) == 0);
    assert(file_info_get_name(info1));
    assert(file_info_get_ref(info1) == 0);

    struct file_info* info2;
    file_index_insert(hash2, &index, &info2);
    assert(memcmp(file_info_get_hash(info2), hash2, size) == 0);
    assert(file_info_get_name(info2));
    assert(file_info_get_ref(info2) == 0);

    struct file_info* info3;
    file_index_insert(hash3, &index, &info3);
    assert(memcmp(file_info_get_hash(info3), hash3, size) == 0);
    assert(file_info_get_name(info3));
    assert(file_info_get_ref(info3) == 0);

    assert(memcmp(file_info_get_name(info1), file_info_get_name(info2), name_size) != 0);
    assert(memcmp(file_info_get_name(info1), file_info_get_name(info3), name_size) != 0);
    assert(memcmp(file_info_get_name(info2), file_info_get_name(info3), name_size) != 0);

    struct file_info* found = NULL;

    file_index_find_by_hash(hash1, &index, &found);
    assert(found == info1);

    file_index_find_by_hash(hash2, &index, &found);
    assert(found == info2);

    file_index_find_by_hash(hash3, &index, &found);
    assert(found == info3);

    file_index_save(&index);

    struct file_index new_index;
    file_index_open(&conf, &new_index);
    assert(file_index_find_by_hash(hash1, &new_index, NULL) == ERROR_NOTFOUND);
    assert(file_index_find_by_hash(hash2, &new_index, NULL) == ERROR_NOTFOUND);
    assert(file_index_find_by_hash(hash3, &new_index, NULL) == ERROR_NOTFOUND);
    file_index_destroy(&new_index);

    char* name1 = NULL;
    char* name2 = NULL;
    char* name3 = NULL;

    file_name_readable(file_info_get_name(info1), name_size, &name1);
    file_name_readable(file_info_get_name(info2), name_size, &name2);
    file_name_readable(file_info_get_name(info3), name_size, &name3);
    assert(name1);
    assert(name2);
    assert(name3);

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

    file_index_open(&conf, &new_index);
    struct file_info* tmp;
    assert(file_index_find_by_hash(hash1, &new_index, &tmp) == ERROR_SUCCESS);
    assert(file_info_get_ref(tmp) == 2);
    assert(memcmp(file_info_get_hash(tmp), file_info_get_hash(info1), size) == 0);
    assert(memcmp(file_info_get_name(tmp), file_info_get_name(info1), name_size) == 0);
    assert(file_index_find_by_hash(hash2, &new_index, &tmp) == ERROR_SUCCESS);
    assert(file_info_get_ref(tmp) == 1);
    assert(memcmp(file_info_get_hash(tmp), file_info_get_hash(info2), size) == 0);
    assert(memcmp(file_info_get_name(tmp), file_info_get_name(info2), name_size) == 0);
    assert(file_index_find_by_hash(hash3, &new_index, NULL) == ERROR_NOTFOUND);
    file_index_destroy(&new_index);

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

    file_index_open(&conf, &new_index);
    assert(file_index_find_by_hash(hash1, &new_index, NULL) == ERROR_NOTFOUND);
    assert(file_index_find_by_hash(hash2, &new_index, NULL) == ERROR_NOTFOUND);
    assert(file_index_find_by_hash(hash3, &new_index, NULL) == ERROR_NOTFOUND);
    file_index_destroy(&new_index);

    assert(access(name1, F_OK) == -1 && errno == ENOENT);
    assert(access(name2, F_OK) == -1 && errno == ENOENT);
    assert(access(name3, F_OK) == -1 && errno == ENOENT);

    file_index_destroy(&index);
    config_destroy(&conf);
    free(name1);
    free(name2);
    free(name3);
    return 0;
}