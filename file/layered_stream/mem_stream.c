#include "mem_stream.h"
#include "layered_stream_def.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

struct layered_stream_mem
{
    struct layered_stream base;
    char** ptr;
    size_t* sizeloc;
    char* buf;
    size_t size;
    size_t max_size;
    size_t rpos;
    size_t wpos;
    int err;
};

size_t layered_stream_mem_read(char* ptr, size_t size, struct layered_stream_mem* stream)
{
    size_t left = stream->size - stream->rpos;
    ssize_t num = left > size ? size : left;
    memcpy(ptr, stream->buf + stream->rpos, num);
    stream->rpos += num;
    return num;
}

size_t layered_stream_mem_write(const char* ptr, size_t size, struct layered_stream_mem* stream)
{
    size_t left = stream->max_size - stream->wpos;
    if(left < size)
    {
        size_t new_size = stream->max_size;
        if(new_size == 0)
        {
            new_size = 1;
        }
        while(new_size < size + stream->wpos)
        {
            new_size *= 2;
        }
        if(new_size < stream->max_size)
        {
            errno = EOVERFLOW;
            stream->err = 1;
            return 0;
        }
        char* new_buf = realloc(stream->buf, new_size);
        if(!new_buf)
        {
            stream->err = 1;
            return 0;
        }
        stream->max_size = new_size;
        stream->buf = new_buf;
        *stream->ptr = new_buf;
    }
    memcpy(stream->buf + stream->wpos, ptr, size);
    stream->wpos += size;
    stream->size += size;
    *stream->sizeloc = stream->size;
    return size;
}

int layered_stream_mem_eof(struct layered_stream_mem* stream)
{
    return stream->rpos == stream->size;
}

int layered_stream_mem_error(struct layered_stream_mem* stream)
{
    return stream->err;
}

void layered_stream_mem_clearerr(struct layered_stream_mem* stream)
{
    stream->err = 0;
}

int layered_stream_mem_close(struct layered_stream_mem* stream)
{
    free(stream);
    return 0;
}

const struct layered_stream_call_tab layered_stream_call_tab_mem =
        {
                .read_func      = (size_t (*)(char *, size_t, struct layered_stream *))        layered_stream_mem_read,
                .write_func     = (size_t (*)(const char *, size_t, struct layered_stream *))  layered_stream_mem_write,
                .eof_func       = (int (*)(struct layered_stream *))                            layered_stream_mem_eof,
                .error_func     = (int (*)(struct layered_stream *))                            layered_stream_mem_error,
                .clearerr_func  = (void (*)(struct layered_stream *))                           layered_stream_mem_clearerr,
                .close_func     = (int (*)(struct layered_stream *))                            layered_stream_mem_close
        };

struct layered_stream_mem* layered_stream_mem_open(char** ptr, size_t* sizeloc)
{
    assert(ptr);
    assert(sizeloc);
    struct layered_stream_mem* stream = malloc(sizeof(struct layered_stream_mem));
    if(!stream)
    {
        return NULL;
    }
    stream->buf = NULL;
    stream->size = 0;
    stream->max_size = 0;
    stream->ptr = ptr;
    stream->sizeloc = sizeloc;
    stream->rpos = 0;
    stream->wpos = 0;
    stream->err = 0;
    stream->base.source = NULL;
    stream->base.calls = &layered_stream_call_tab_mem;
    *ptr = NULL;
    *sizeloc = 0;
    return stream;
}

struct layered_stream_mem* layered_stream_mem_open_reuse(char** ptr, size_t* sizeloc)
{
    assert(ptr);
    assert(sizeloc);
    struct layered_stream_mem* stream = malloc(sizeof(struct layered_stream_mem));
    if(!stream)
    {
        return NULL;
    }
    stream->buf = *ptr;
    stream->size = *sizeloc;
    stream->max_size = *sizeloc;
    stream->ptr = ptr;
    stream->sizeloc = sizeloc;
    stream->rpos = 0;
    stream->wpos = *sizeloc;
    stream->err = 0;
    stream->base.source = NULL;
    stream->base.calls = &layered_stream_call_tab_mem;
    return stream;
}
