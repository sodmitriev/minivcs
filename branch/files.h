#ifndef MINIVCS_FILES_H
#define MINIVCS_FILES_H

#include <stddef.h>
#include <config/config.h>


struct file_index
{

};

struct file_info
{
    char* path;
    size_t ref_count;
};

extern int init_file_index(const struct config* conf, struct file_index* index);

extern int open_file_index(const struct config* conf, struct file_index* index);

extern int close_file_index(struct file_index* index);



extern int add_file_to_index(struct file_info* file, struct file_index* index); //ref++

extern int rm_file_from_index(struct file_info* file, struct file_index* index); //ref--



extern int new_file_info(const char* path, struct file_info* file);

extern int open_file_info(const char* path, const struct file_index* index);

extern int close_file_info(struct file_info* file); //delete if ref == 0

#endif //MINIVCS_FILES_H
