/*
 * Authors:
 *     Eric Richter, erichte@us.ibm.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fuse/cuse_lowlevel.h>

#define MAX_BUF_SIZE 128

static int example_size = sizeof("Hello World!\n");
static char example_buffer[MAX_BUF_SIZE] = "Hello World!\n";

static void c_open(fuse_req_t req, struct fuse_file_info *fi)
{
    fuse_reply_open(req, fi);
}

// TODO: figure out what goes in this call...
static void c_release(fuse_req_t req, struct fuse_file_info * fi) {}

static void c_read(fuse_req_t req, size_t size, off_t off, struct fuse_file_info *fi)
{

    // TODO: Check offset

    fuse_reply_buf(req, example_buffer, example_size);

}

static void c_write(fuse_req_t req, const char * buf, size_t size, off_t off, struct fuse_file_info *fi)
{
    if (size > MAX_BUF_SIZE)
        fuse_reply_write(req, 0);

    memcpy(example_buffer, buf, size);
    example_size = size;
    fuse_reply_write(req, size);
}

static void c_ioctl(fuse_req_t req, int cmd, void *arg, struct fuse_file_info *fi, unsigned int flags, const void * in_buf, size_t in_bufsz, size_t out_butsz)
{

    switch(cmd) {
    // Random ioctl number for testing purposes
    case 424242:
        // Sets the internal buffer, check with a read
        sprintf(example_buffer, "424242 received\n");
        example_size = sizeof("424242 received\n");
        break;
    default:
        // some default action?
        break;
    }

}

static struct cuse_info cinfo = {
    .dev_major = 42,
    .dev_minor = 0,
    .dev_info_argc = 1,
    .flags = 0,
};

static const struct cuse_lowlevel_ops clops = {
    .open = c_open,
    .release = c_release,
    .read = c_read,
    .write = c_write,
    .ioctl = c_ioctl,
};


int main(int argc, char **argv)
{
    char *foo[1];

    cinfo.dev_info_argv = (const char**) foo;

    if (argc != 2) {
        fprintf(stderr, "Device name required as arugment\n");
        return 1;
    }

    /* DEVNAME=foobar creates /dev/foobar, needs to be passed as cuse_info argv,
      *  not cuse_lowlevel_main argv
      */
    foo[0] = calloc(1,sizeof("DEVNAME=") + strlen(argv[1]) + 1);
    strcpy(foo[0], "DEVNAME=");
    strcat(foo[0], argv[1]);

    return cuse_lowlevel_main(1, argv, &cinfo, &clops, NULL);
}

