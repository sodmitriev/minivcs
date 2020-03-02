#ifndef MINIVCS_LAYERED_STREAM_DEF_H
#define MINIVCS_LAYERED_STREAM_DEF_H

struct layered_stream_call_tab
{
    size_t (*read_func)(char *ptr, size_t size, struct layered_stream* stream);
    size_t (*write_func)(const char* ptr, size_t size, struct layered_stream* stream);
    int (*eof_func)(struct layered_stream* stream);
    int (*error_func)(struct layered_stream* stream);
    void (*clearerr_func)(struct layered_stream* stream);
    int (*close_func)(struct layered_stream* stream);
};

struct layered_stream
{
    struct layered_stream* source;
    const struct layered_stream_call_tab* calls;
};

#endif //MINIVCS_LAYERED_STREAM_DEF_H
