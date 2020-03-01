#include "storage.h"
#include <ec.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

int cp(const char *to, const char *from)
{
    int fd_to, fd_from;
    char buf[4096];
    ssize_t nread;
    int saved_errno;

    fd_from = open(from, O_RDONLY);
    if (fd_from < 0)
        return -1;

    fd_to = open(to, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (fd_to < 0)
        goto out_error;

    while (nread = read(fd_from, buf, sizeof buf), nread > 0)
    {
        char *out_ptr = buf;
        ssize_t nwritten;

        do {
            nwritten = write(fd_to, out_ptr, nread);

            if (nwritten >= 0)
            {
                nread -= nwritten;
                out_ptr += nwritten;
            }
            else if (errno != EINTR)
            {
                goto out_error;
            }
        } while (nread > 0);
    }

    if (nread == 0)
    {
        if (close(fd_to) < 0)
        {
            fd_to = -1;
            goto out_error;
        }
        close(fd_from);

        /* Success! */
        return 0;
    }

    out_error:
    saved_errno = errno;

    close(fd_from);
    if (fd_to >= 0)
        close(fd_to);

    errno = saved_errno;
    return -1;
}

int store_file(const char* storage, const char* path)
{
    if(cp(storage, path) == -1)
    {
        return ERROR_SYSTEM;
    }
    return ERROR_SUCCESS;
}

int restore_file(const char* storage, const char* path)
{
    if(rename(storage, path) == 0)
    {
        return ERROR_SUCCESS;
    }
    if(cp(path, storage) == -1)
    {
        return ERROR_SYSTEM;
    }
    return ERROR_SUCCESS;
}

int reset_storage(const char* storage)
{
    if(unlink(storage) < 0)
    {
        return ERROR_SYSTEM;
    }
    return ERROR_SUCCESS;
}