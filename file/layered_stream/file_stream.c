#include "file_stream.h"
#include "layered_stream_def.h"
#include <stdio.h>
#include <stdlib.h>

struct layered_stream_file
{
    struct layered_stream base;
    FILE* file;
};

size_t layered_stream_file_read(char* ptr, size_t size, struct layered_stream_file* stream)
{
    return fread(ptr, 1, size, stream->file);
}

size_t layered_stream_file_write(const char* ptr, size_t size, struct layered_stream_file* stream)
{
    return fwrite(ptr, 1, size, stream->file);
}

int layered_stream_file_eof(struct layered_stream_file* stream)
{
    return feof(stream->file);
}

int layered_stream_file_error(struct layered_stream_file* stream)
{
    return ferror(stream->file);
}

void layered_stream_file_clearerr(struct layered_stream_file* stream)
{
    clearerr(stream->file);
}

int layered_stream_file_close(struct layered_stream_file* stream)
{
    int err = fclose(stream->file);
    free(stream);
    return err;
}

const struct layered_stream_call_tab layered_stream_call_tab_file =
{
    .read_func      = (size_t (*)(char *, size_t, struct layered_stream *))        layered_stream_file_read,
    .write_func     = (size_t (*)(const char *, size_t, struct layered_stream *))  layered_stream_file_write,
    .eof_func       = (int (*)(struct layered_stream *))                            layered_stream_file_eof,
    .error_func     = (int (*)(struct layered_stream *))                            layered_stream_file_error,
    .clearerr_func  = (void (*)(struct layered_stream *))                           layered_stream_file_clearerr,
    .close_func     = (int (*)(struct layered_stream *))                            layered_stream_file_close
};

struct layered_stream_file* layered_stream_file_open(const char *pathname, const char *mode)
{
    struct layered_stream_file* stream = malloc(sizeof(struct layered_stream_file));
    if(!stream)
    {
        return NULL;
    }
    FILE* file = fopen(pathname, mode);
    if(!file)
    {
        free(stream);
        return NULL;
    }
    stream->base.source = NULL;
    stream->base.calls = &layered_stream_call_tab_file;
    stream->file = file;
    return stream;
}
