#include "file_stream.h"
#include "crypto_stream.h"
#include <stdio.h>
#include <zconf.h>
#include <assert.h>
#include <string.h>

int main()
{
    const char msg[] = "0000000000000000"
                       "1111111111111111"
                       "2222222222222222"
                       "3333333333333333"
                       "4444444444444444"
                       "5555555555555555"
                       "6666666666666666"
                       "7777777777777777"
                       "8888888888888888"
                       "9999999999999999"
                       "aaaaaaaaaaaaaaaa"
                       "bbbbbbbbbbbbbbbb"
                       "cccccccccccccccc"
                       "dddddddddddddddd"
                       "eeeeeeeeeeeeeeee"
                       "fffffff";

    char buf[sizeof(msg)];
    //File test
    {
        lrdstream *stream = layered_stream_file_open("test", "w");
        assert(stream);
        assert(layered_stream_write(msg, sizeof(msg), stream) == sizeof(msg));
        assert(layered_stream_error(stream) == 0);
        assert(layered_stream_close(stream) == 0);

        stream = layered_stream_file_open("test", "r");
        assert(stream);
        assert(layered_stream_read(buf, sizeof(buf), stream) == sizeof(msg));
        assert(layered_stream_error(stream) == 0);
        assert(strcmp(msg, buf) == 0);
        assert(layered_stream_close(stream) == 0);

        lrdstream *stream_in = layered_stream_file_open("test", "r");
        lrdstream *stream_out = layered_stream_file_open("test_out", "w");
        assert(stream_in);
        assert(stream_out);
        assert(layered_stream_send(stream_in, stream_out) == 0);
        assert(layered_stream_close(stream_in) == 0);
        assert(layered_stream_close(stream_out) == 0);

        stream = layered_stream_file_open("test_out", "r");
        assert(stream);
        assert(layered_stream_read(buf, sizeof(buf), stream) == sizeof(msg));
        assert(layered_stream_error(stream) == 0);
        assert(strcmp(msg, buf) == 0);
        assert(layered_stream_close(stream) == 0);

        unlink("test");
        unlink("test_out");
    }
    //Crypto test
    {
        lrdstream *stream_f = layered_stream_file_open("test", "w");
        assert(stream_f);
        lrdstream *stream = layered_stream_crypto_open(stream_f, "aes-256-cbc", "sha1", "mykey", 1);
        assert(stream);
        assert(layered_stream_write(msg, sizeof(msg), stream) == sizeof(msg));
        assert(layered_stream_error(stream) == 0);
        assert(layered_stream_close(stream) == 0);

        stream_f = layered_stream_file_open("test", "r");
        assert(stream);
        stream = layered_stream_crypto_open(stream_f, "aes-256-cbc", "sha1", "mykey", 0);
        assert(stream);
        assert(layered_stream_read(buf, sizeof(buf), stream) == sizeof(msg));
        assert(layered_stream_error(stream) == 0);
        assert(strcmp(msg, buf) == 0);
        assert(layered_stream_close(stream) == 0);

        stream_f = layered_stream_file_open("test", "r");
        assert(stream);
        stream = layered_stream_crypto_open(stream_f, "aes-256-cbc", "sha1", "mykey", 0);
        assert(stream);
        assert(layered_stream_read(buf, 4, stream) == 4);
        assert(layered_stream_error(stream) == 0);
        assert(layered_stream_read(buf + 4, sizeof(buf) - 8, stream) == sizeof(buf) - 8);
        assert(layered_stream_error(stream) == 0);
        assert(layered_stream_read(buf + sizeof(buf) - 4, 4, stream) == 4);
        assert(layered_stream_error(stream) == 0);
        assert(strcmp(msg, buf) == 0);
        assert(layered_stream_close(stream) == 0);

        unlink("test");
    }
    return 0;
}
