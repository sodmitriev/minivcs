#ifndef MINIVCS_LAYERED_STREAM_H
#define MINIVCS_LAYERED_STREAM_H

#include <stddef.h>
#include <sys/types.h>

struct layered_stream;

typedef struct layered_stream lrdstream;

extern ssize_t layered_stream_read(char *ptr, size_t size, lrdstream* stream);

extern ssize_t layered_stream_write(const char* ptr, size_t size, lrdstream* stream);

extern int layered_stream_eof(lrdstream* stream);

extern int layered_stream_error(lrdstream* stream);

extern void layered_stream_clearerr(lrdstream* stream);

extern int layered_stream_close(lrdstream* stream);

extern int layered_stream_send(lrdstream* src, lrdstream* dest);


#endif //MINIVCS_LAYERED_STREAM_H
