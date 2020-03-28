#ifndef MINIVCS_STORAGE_H
#define MINIVCS_STORAGE_H

extern int cp(const char *to, const char *from);

extern void store_file(const char* storage, const char* path);

extern void restore_file(const char* storage, const char* path);

extern void reset_storage(const char* storage);

#endif //MINIVCS_STORAGE_H
