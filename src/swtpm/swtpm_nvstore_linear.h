#ifndef _SWTPM_NVSTORE_LINEAR_H
#define _SWTPM_NVSTORE_LINEAR_H

#include <libtpms/tpm_types.h>

#define SWTPM_NVSTORE_LINEAR_MAGIC 0x737774706d6c696e /* 'swtpmlin' */
#define SWTPM_NVSTORE_LINEAR_VERSION 1
/* TODO: Make this user configurable? */
#define SWTPM_NVSTORE_LINEAR_MAX_STATES 15 /* 3 files per TPM = 5 TPMs */

struct nvram_linear_hdr_file {
    uint32_t offset; /* offset from beginning of file - 0 means unallocated */
    uint32_t data_length; /* length of actually valid data */
    uint32_t section_length; /* length until next file */
} __attribute__((packed));

/*
    Represents a file header for a multi-part file format storing TPM states
    within one linear address space. Stored in little-endian.
*/
struct nvram_linear_hdr {
    uint64_t magic;
    uint8_t  version;
    uint8_t  _padding; /* at least align to 32 */
    uint16_t hdrsize;

    struct nvram_linear_hdr_file files[SWTPM_NVSTORE_LINEAR_MAX_STATES];
} __attribute__((packed));

/*
    Implementation ops for linear data backends. The "linear" backend takes care
    of the allocation strategy to pack multiple files/parts into one address
    space, implementations only need to make sure that the linearized data is
    written and accessed correctly.
*/
struct nvram_linear_store_ops {
    /*
        Called once upon initialization, if the URI prefix (e.g. file://)
        matches the implementation. 'uri' is the raw, prefixed backend_uri
        string. 'data' and 'length' should be set to a memory region that
        contains the loaded data in it's entirety (e.g. when loaded from a file,
        the mmap base address and file length).
        If a new store is created, it must contain at least enough space to
        store 'sizeof(struct nvram_linear_hdr)' bytes.
    */
    TPM_RESULT (*open)(const char* uri,
                       unsigned char **data,
                       uint32_t *length);

    /*
        Called whenever the data in the provided buffer has changed. Will be
        called for every changed region, offset is relative to base (0 is for
        header or full flushes). Can be left unimplemented if data stored in
        given buffer is flushed automatically.
    */
    TPM_RESULT (*flush)(const char* uri,
                        uint32_t offset,
                        uint32_t count);

    /*
       Called whenever space has been freed or more space is required to store
       data. Implementations can choose to leave this unimplemented, or make the
       implementation a no-op, TPM_SIZE should be returned if 'requested_length'
       can not be made available. 'data' and 'new_length' must be set similar to
       open(), either to the same region or a different one (in case of remap or
       similar).
    */
    TPM_RESULT (*resize)(const char* uri,
                         unsigned char **data,
                         uint32_t *new_length,
                         uint32_t requested_length);

    /*
        Called when the instance should be closed, e.g. at program exit. No
        further calls to other ops will be made after this one.
    */
    void (*cleanup)(void);
};

/* available store interfaces */
extern struct nvram_linear_store_ops nvram_linear_file_ops;

#endif /* _SWTPM_NVSTORE_LINEAR_H */
