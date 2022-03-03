/*
 * daemonize.c -- Utility functions for race-free daemonization
 *
 * (c) Two Sigma Open Source, LLC 2021.
 *
 * Author: Nicolas Williams <nico@twosigma.com>
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

#include "config.h"

#include "daemonize.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * daemon(3) is racy because it fork()s and exits in the parent before the
 * child can get ready to provide its services.
 *
 * Not every daemon can set up services before calling daemon(3), as some
 * APIs are not fork-safe and must be called in the child-side of the
 * daemon(3)'s fork() calls.
 *
 * Even if a daemon can set up services before calling daemon(3), it will not
 * be able to write the correct PID into a pidfile until after daemon(3)
 * returns.
 *
 * E.g.,
 *
 *  #!/bin/bash
 *
 *  # Start a service:
 *  some-serviced --daemon --pid=... ...
 *
 *  # Call it:
 *  call-some-service ping || echo "oops, we won the race but lost the game"
 *
 * To address this we split daemon(3) into two functions, daemonize_prep() and
 * daemonize_finish().  A daemon program should call daemonize_prep() early
 * when it knows it will have to daemonize (e.g., because of a --daemon
 * command-line option), then it should do all the setup required to start
 * providing its services, then it should call daemonize_finish().
 *
 * These two functions do all that daemon(3) does, but in two phases so that
 * the original process that calls daemonize_prep() does not exit until the
 * service is ready.
 *
 * daemonize_prep() calls fork(), setsid(), and then forks again, and returns
 * in the grandchild, but exits in the original and middle processes when the
 * grandchild calls daemonize_finish().
 *
 * How to use this:
 *
 *  if (daemonize) {
 *      pid_t old_pid, new_pid;
 *
 *      old_pid = getpid();
 *      if (daemonize_prep() == -1)
 *          err(1, "Failed to daemonize");
 *
 *      // We're now in a grandchild, but the original parent should still be
 *      // waiting.
 *      new_pid = getpid();
 *      assert(old_pid != new_pid);
 *  }
 *
 *  // setup sockets, listen() on them, etc...
 *  my_setup_service_and_listen_on_sockets();
 *
 *  // Tell the waiting parent and grandparent that we're ready:
 *  // (doing this even if daemonize_prep() wasn't called is ok)
 *  daemonize_finish();
 *
 *  // daemonize_finish() did not fork() again:
 *  assert(new_pid == getpid());
 *
 * Note: the processes that exit will use _exit().  The process that
 * daemonize_prep() returns to should be able to use exit().
 */

static int devnullfd = -1;
static int pfd = -1;

static int
wait_or_die_like_it(pid_t pid)
{
    int status;

    while (waitpid(pid, &status, 0) == -1) {
        if (errno == EINTR)
            continue;
        /* XXX Should just use err(3). */
        fprintf(stderr, "waitpid() failed: %s\n", strerror(errno));
        fflush(stderr);
        _exit(1);
    }
    if (WIFSIGNALED(status)) {
        /*
         * Child died in a fire; die like it so the parent sees the same exit
         * status.
         */
        kill(getpid(), WTERMSIG(status));
    }
    if (!WIFEXITED(status)) {
        /* If fire doesn't kill us, _exit(). */
        _exit(1);
    }
    /* Child exited willingly. */
    return WEXITSTATUS(status);
}

/*
 * Prepare to daemonize.  When ready, the caller should call
 * daemonize_finish().
 *
 * This arranges for the parent to exit when and only when the child is ready
 * to service clients.
 *
 * This forks a grandchild and returns in the grandchild
 * but exits in the parent and grandparent, but only once the child calls
 * daemonize_finish() (or exits/dies, whichever comes first).
 *
 * Because the parent side of the fork() calls _exit(), the child can exit().
 *
 * Returns -1 on error (sets errno), 0 on success.
 */
int
daemonize_prep(void)
{
    ssize_t bytes;
    char buf;
    int save_errno = errno;
    int pfds[2] = { -1, -1 };
    pid_t pid;

    /*
     * Be idempotent.  If called twice because, e.g., --daemon is given twice,
     * do nothing the second time.
     */
    if (pfd != -1)
        return 0;

    /* Grand parent process. */
    fflush(stdout);
    fflush(stderr);
    pid = fork();
    if (pid == (pid_t)-1) {
        fprintf(stderr, "Failed to daemonize: Failed to fork: %s\n",
                strerror(errno));
        return -1;
    }

    if (pid != 0) {
        /*
         * Grand parent process: exit when the grandchild is ready or die in
         * the same way.
         */
        _exit(wait_or_die_like_it(pid));
    }

    /* Intermediate process.  Detach from tty, fork() again. */
    if (setsid() == -1) {
        fprintf(stderr, "Failed to daemonize: Failed to detach from tty: %s\n",
                strerror(errno));
        _exit(1);
    }

    /* Set things up so the grandchild can finish daemonizing. */
    devnullfd = open("/dev/null", O_RDWR);
    if (devnullfd == -1) {
        fprintf(stderr, "Failed to daemonize: Could not open /dev/null: %s\n",
                strerror(errno));
        _exit(1);
    }
    if (pipe(pfds) == -1) {
        fprintf(stderr, "Failed to daemonize: Could not make a pipe: %s\n",
                strerror(errno));
        _exit(1);
    }
    pfd = pfds[1];

    /* Fork the grandchild so it cannot get a controlling tty by accident. */
    pid = fork();
    if (pid == (pid_t)-1) {
        fprintf(stderr, "Failed to daemonize: Could not fork: %s\n",
                strerror(errno));
        _exit(1);
    }
    if (pid != 0) {
        /*
         * Middle process.
         *
         * Wait for ready notification from the child, then _exit()
         * accordingly.
         */
        (void) close(pfds[1]);
        do {
            bytes = read(pfds[0], &buf, sizeof(buf));
        } while (bytes == -1 && errno == EINTR);
        if (bytes < 0) {
            fprintf(stderr, "Failed to daemonize: "
                    "Error reading from pipe: %s\n", strerror(errno));
            /* Let init reap the grandchild. */
            _exit(1);
        }
        if (bytes == 0) {
            /* Die like the grandchild. */
            _exit(wait_or_die_like_it(pid));
        }
        /* Ready! */
        _exit(0);
    }

    /*
     * We're on the grandchild side now, and we'll return with the expectation
     * that the caller will call daemonize_finish().  The parent, which will
     * continue executing this function, will _exit() when the child indicates
     * that it is ready.
     */
    (void) close(pfds[0]);
    errno = save_errno;
    return 0;
}

/*
 * Indicate that the service is now ready.
 *
 * Will cause the ancestor processes waiting in daemonize_prep() to _exit().
 */
void
daemonize_finish(void)
{
    ssize_t bytes;
    int save_errno = errno;

    /* pfds[1] will be > -1 IFF daemonize_prep() was called */
    if (pfd == -1) {
        return;
    }

    if (dup2(devnullfd, STDOUT_FILENO) == -1) {
        fprintf(stderr, "Failed to redirect output stream to /dev/null: %s\n",
                strerror(errno));
        fflush(stderr);
        exit(1);
    }
    if (dup2(devnullfd, STDERR_FILENO) == -1) {
        fprintf(stderr, "Failed to redirect error stream to /dev/null: %s\n",
                strerror(errno));
        fflush(stderr);
        exit(1);
    }
    (void) close(devnullfd);
    devnullfd = -1;

    do {
        bytes = write(pfd, "", sizeof(""));
    } while (bytes == -1 && errno == EINTR);
    if (bytes <= 0) {
        /* There's no point writing to stderr now that it goes to /dev/null */
        exit(1);
    }
    (void) close(pfd);
    pfd = -1;
    errno = save_errno;
}
