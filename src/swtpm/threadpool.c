/*
 * threadpool.c -- threadpool
 *
 * (c) Copyright IBM Corporation 2015.
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the names of the IBM Corporation nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdbool.h>

#include <glib.h>

#include "threadpool.h"

/* whether the worker thread is busy processing a command */
static bool thread_busy;

/* thread pool with one single TPM thread */
GThreadPool *pool;

#if GLIB_MAJOR_VERSION >= 2
# if GLIB_MINOR_VERSION >= 32

GCond thread_busy_signal;
GMutex thread_busy_lock;
#  define THREAD_BUSY_SIGNAL &thread_busy_signal
#  define THREAD_BUSY_LOCK &thread_busy_lock

# else

GCond *thread_busy_signal;
GMutex *thread_busy_lock;
#  define THREAD_BUSY_SIGNAL thread_busy_signal
#  define THREAD_BUSY_LOCK thread_busy_lock

# endif
#else

#error Unsupport glib version

#endif

/*
 * worker_thread_wait_done: wait until the worker thread is done
 */
void worker_thread_wait_done(void)
{
    g_mutex_lock(THREAD_BUSY_LOCK);
    while (thread_busy) {
#if GLIB_MINOR_VERSION >= 32
        gint64 end_time = g_get_monotonic_time() +
            1 * G_TIME_SPAN_SECOND;
        g_cond_wait_until(THREAD_BUSY_SIGNAL,
                          THREAD_BUSY_LOCK,
                          end_time);
#else
        GTimeVal abs_time;
        /*
         * seems like occasionally the g_cond_signal did not wake up
         * the sleeping task; so we poll [TIS Test in BIOS]
         */
        abs_time.tv_sec = 1;
        abs_time.tv_usec = 0;
        g_cond_timed_wait(THREAD_BUSY_SIGNAL,
                          THREAD_BUSY_LOCK,
                          &abs_time);
#endif
    }
    g_mutex_unlock(THREAD_BUSY_LOCK);
}

/*
 * worker_thread_mark_busy: mark the workder thread as busy
 */
void worker_thread_mark_busy(void)
{
    g_mutex_lock(THREAD_BUSY_LOCK);
    thread_busy = true;
    g_mutex_unlock(THREAD_BUSY_LOCK);
}

/*
 * work_tread_mark_done: mark the worker thread as having completed
 *
 * Mark the worker thread as done and wake up the waiting thread.
 */
void worker_thread_mark_done(void)
{
    g_mutex_lock(THREAD_BUSY_LOCK);
    thread_busy = false;
    g_cond_signal(THREAD_BUSY_SIGNAL);
    g_mutex_unlock(THREAD_BUSY_LOCK);
}

/*
 * worker_thread_is_busy: is the worker thread busy?
 *
 * Determine whether the worker thread is busy.
 */
int worker_thread_is_busy(void)
{
    return thread_busy;
}

/*
 * worker_thread_end: cleanup once worker thread is all done
 */
void worker_thread_end(void)
{
    if (pool) {
        worker_thread_wait_done();
        g_thread_pool_free(pool, TRUE, TRUE);
        pool = NULL;
    }
}

void worker_thread_init(void)
{
#if GLIB_MINOR_VERSION >= 32
    g_mutex_init(THREAD_BUSY_LOCK);
    g_cond_init(THREAD_BUSY_SIGNAL);
#else
    g_thread_init(NULL);
    THREAD_BUSY_LOCK = g_mutex_new();
    THREAD_BUSY_SIGNAL = g_cond_new();
#endif
}
