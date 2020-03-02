#include "layered_stream.h"
#include "layered_stream_def.h"

#define SEND_BUFFER_SIZE 4096

size_t layered_stream_read(char* ptr, size_t size, struct layered_stream* stream)
{
    return stream->calls->read_func(ptr, size, stream);
}

size_t layered_stream_write(const char* ptr, size_t size, struct layered_stream* stream)
{
    return stream->calls->write_func(ptr, size, stream);
}

int layered_stream_eof(struct layered_stream* stream)
{
    return stream->calls->eof_func(stream);
}

int layered_stream_error(struct layered_stream* stream)
{
    return stream->calls->error_func(stream);
}

void layered_stream_clearerr(lrdstream* stream)
{
    stream->calls->clearerr_func(stream);
}

int layered_stream_close(struct layered_stream* stream)
{
    return stream->calls->close_func(stream);
}

extern int layered_stream_send(lrdstream* src, lrdstream* dest)
{
    char buf[SEND_BUFFER_SIZE];
    size_t num;
    while((num = layered_stream_read(buf, sizeof(buf), src)) > 0)
    {
        if(layered_stream_write(buf, num, dest) < 0)
        {
            return -1;
        }
    }
    if(layered_stream_error(src))
    {
        return -1;
    }
    return 0;
}
