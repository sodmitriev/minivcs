#ifndef MINIVCS_CRYPTO_STREAM_H
#define MINIVCS_CRYPTO_STREAM_H

#include "layered_stream.h"

extern lrdstream* layered_stream_crypto_open(lrdstream* source, const char* cipher, const char* digest, const char* key,
                                             int encrypt);

#endif //MINIVCS_CRYPTO_STREAM_H
