#ifndef MINIVCS_MEM_STREAM_H
#define MINIVCS_MEM_STREAM_H

#include "layered_stream.h"

extern struct layered_stream_mem* layered_stream_mem_open(char** ptr, size_t* sizeloc);

extern struct layered_stream_mem* layered_stream_mem_open_reuse(char** ptr, size_t* sizeloc);

#endif //MINIVCS_MEM_STREAM_H
