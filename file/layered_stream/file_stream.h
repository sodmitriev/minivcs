#ifndef MINIVCS_FILE_STREAM_H
#define MINIVCS_FILE_STREAM_H

#include "layered_stream.h"

extern lrdstream* layered_stream_file_open(const char *pathname, const char *mode);

#endif //MINIVCS_FILE_STREAM_H
