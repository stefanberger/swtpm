/*
 * seccomp_profile.c -- seccomp profile support
 *
 * (c) Copyright IBM Corporation 2019.
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

#include "config.h"

#include <stdbool.h>
#include <string.h>

#ifdef WITH_SECCOMP
# include <seccomp.h>
#endif

#include "logging.h"
#include "utils.h"
#include "seccomp_profile.h"
#include "swtpm_utils.h"

#ifdef WITH_SECCOMP
static int create_seccomp_profile_add_rules(scmp_filter_ctx ctx,
                                            int *syscalls, size_t syscalls_len,
                                            unsigned int action)
{
    int ret = 0;
    unsigned i = 0;
    uint32_t act = SCMP_ACT_KILL;

#ifdef SCMP_ACT_LOG
    if (action == SWTPM_SECCOMP_ACTION_LOG)
        act = SCMP_ACT_LOG;
#endif

    for (i = 0; i < syscalls_len; i++) {
        ret = seccomp_rule_add(ctx, act, syscalls[i], 0);
        if (ret < 0) {
            logprintf(STDERR_FILENO,
                      "seccomp_rule_add failed with errno %d: %s\n",
                      -ret, strerror(-ret));
            break;
        }
    }
    return ret;
}

/*
 * create_seccomp_profile: Build a blacklist of syscalls
 *
 * cusetpm: whether to build for the CUSE tpm
 * action: the seccomp action
 */
int create_seccomp_profile(bool cusetpm, unsigned int action)
{
    int blacklist[] = {
        /* high concern */
        SCMP_SYS(capset),
        SCMP_SYS(pivot_root),
        SCMP_SYS(chroot),
        SCMP_SYS(settimeofday),
        SCMP_SYS(clock_adjtime),
        SCMP_SYS(clock_settime),
#ifdef __NR_clock_settime64
        SCMP_SYS(clock_settime64),
#endif
        SCMP_SYS(adjtimex),
        SCMP_SYS(mount),
        SCMP_SYS(umount2),
#ifdef __NR_fsmount
        SCMP_SYS(fsmount),
#endif
#ifdef __NR_move_mount
        SCMP_SYS(move_mount),
#endif
        SCMP_SYS(swapon),
        SCMP_SYS(swapoff),
        SCMP_SYS(reboot),
        SCMP_SYS(tgkill),
        SCMP_SYS(kexec_load),
        SCMP_SYS(unshare),
        SCMP_SYS(setns),
        SCMP_SYS(kcmp),
        SCMP_SYS(init_module),
        SCMP_SYS(finit_module),
        SCMP_SYS(delete_module), 
        SCMP_SYS(seccomp),
        SCMP_SYS(kexec_file_load),
#ifdef __NR_sysctl
        SCMP_SYS(sysctl),
#endif
        /* semaphores and messages queues */
        SCMP_SYS(semget),
        SCMP_SYS(semop),
        SCMP_SYS(shmget),
        SCMP_SYS(shmat),
        SCMP_SYS(shmctl),
        SCMP_SYS(shmdt),
        SCMP_SYS(msgget),
        SCMP_SYS(msgsnd),
        SCMP_SYS(msgrcv),
        SCMP_SYS(msgctl),
        SCMP_SYS(mq_open),
        SCMP_SYS(mq_unlink),
        SCMP_SYS(mq_timedsend),
        SCMP_SYS(mq_timedreceive),
        SCMP_SYS(mq_notify),
        SCMP_SYS(mq_getsetattr),
        /* misc */
        SCMP_SYS(ptrace),
        SCMP_SYS(syslog),
        SCMP_SYS(capget),
        SCMP_SYS(capset),
        SCMP_SYS(sigaltstack),
        SCMP_SYS(personality),
        SCMP_SYS(sysfs),
        SCMP_SYS(getpriority),
        SCMP_SYS(setpriority),
        SCMP_SYS(sched_setparam),
        SCMP_SYS(sched_setscheduler),
        SCMP_SYS(sched_setaffinity),
        SCMP_SYS(vhangup),
        SCMP_SYS(sethostname),
        SCMP_SYS(setdomainname),
        SCMP_SYS(quotactl),
        SCMP_SYS(readahead),
        SCMP_SYS(lookup_dcookie),
        SCMP_SYS(add_key),
        SCMP_SYS(request_key),
        SCMP_SYS(keyctl),
        SCMP_SYS(inotify_init),
        SCMP_SYS(inotify_init1),
        SCMP_SYS(inotify_add_watch),
        SCMP_SYS(inotify_rm_watch),
        SCMP_SYS(splice),
        SCMP_SYS(tee),
        SCMP_SYS(vmsplice),
        SCMP_SYS(signalfd),
        SCMP_SYS(eventfd),
        SCMP_SYS(timerfd_settime),
#ifdef __NR_timer_settime64
        SCMP_SYS(timer_settime64),
#endif
#ifdef __NR_timerfd_settime64
        SCMP_SYS(timerfd_settime64),
#endif
        SCMP_SYS(timerfd_gettime),
        SCMP_SYS(signalfd4),
        SCMP_SYS(eventfd2),
        SCMP_SYS(fanotify_init),
        SCMP_SYS(fanotify_mark),
        SCMP_SYS(mknod),
        SCMP_SYS(mknodat),
        SCMP_SYS(acct),
        SCMP_SYS(prlimit64),
        SCMP_SYS(setrlimit),
#ifdef __NR_bpf
        SCMP_SYS(bpf),
#endif
#ifdef __NR_copy_filerange
        SCMP_SYS(copy_filerange),
#endif
        /* xattrs */
        SCMP_SYS(setxattr),
        SCMP_SYS(lsetxattr),
        SCMP_SYS(fsetxattr),
        SCMP_SYS(getxattr),
        SCMP_SYS(lgetxattr),
        SCMP_SYS(fgetxattr),
        SCMP_SYS(listxattr),
        SCMP_SYS(llistxattr),
        SCMP_SYS(flistxattr),
        SCMP_SYS(removexattr),
        SCMP_SYS(lremovexattr),
        SCMP_SYS(fremovexattr),
        /* processs forking */
        SCMP_SYS(execve),
        /* io */
        SCMP_SYS(iopl),
        SCMP_SYS(ioperm),
        SCMP_SYS(io_setup),
        SCMP_SYS(io_destroy),
        SCMP_SYS(io_getevents),
        SCMP_SYS(io_submit),
        SCMP_SYS(io_cancel),
        SCMP_SYS(ioprio_set),
        SCMP_SYS(ioprio_get),
        /* not implemented, removed */
        SCMP_SYS(create_module),
        SCMP_SYS(get_kernel_syms),
        SCMP_SYS(query_module),
        SCMP_SYS(uselib),
        SCMP_SYS(nfsservctl),
        SCMP_SYS(getpmsg),
        SCMP_SYS(putpmsg),
        SCMP_SYS(afs_syscall),
        SCMP_SYS(tuxcall),
        SCMP_SYS(security),
        SCMP_SYS(set_thread_area),
        SCMP_SYS(get_thread_area),
        SCMP_SYS(epoll_ctl_old),
        SCMP_SYS(epoll_wait_old),
        SCMP_SYS(vserver),
        /* privileged */
        SCMP_SYS(setuid),
        SCMP_SYS(setgid),
        SCMP_SYS(setpgid),
        SCMP_SYS(setsid),
        SCMP_SYS(setreuid),
        SCMP_SYS(setregid),
        SCMP_SYS(setgroups),
        SCMP_SYS(setresuid),
        SCMP_SYS(setresgid),
        SCMP_SYS(setfsuid),
        SCMP_SYS(setfsgid)
    };
    /* CUSE TPM needs to clone or fork */
    int blacklist_noncuse[] = {
        SCMP_SYS(clone),
        SCMP_SYS(fork),
        SCMP_SYS(vfork),
        SCMP_SYS(prctl),
#ifdef __NR_clone3
        SCMP_SYS(clone3),
#endif
        /* misc */
        SCMP_SYS(sched_setattr), /* caller: g_thread_pool_new() glib v2.68 */
    };
    scmp_filter_ctx ctx;
    int ret;

    if (action == SWTPM_SECCOMP_ACTION_NONE)
        return 0;

    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        logprintf(STDERR_FILENO, "seccomp_init failed\n");
        return -1;
    }

    if ((ret = create_seccomp_profile_add_rules(ctx, blacklist,
                                                ARRAY_LEN(blacklist),
                                                action)) < 0)
        goto error_seccomp_rule_add;

    if (!cusetpm &&
        (ret = create_seccomp_profile_add_rules(ctx, blacklist_noncuse,
                                                ARRAY_LEN(blacklist_noncuse),
                                                action)) < 0)
        goto error_seccomp_rule_add;

    if ((ret = seccomp_load(ctx)) < 0)
        logprintf(STDERR_FILENO, "seccomp_load failed with errno %d: %s\n",
                  -ret, strerror(-ret));

error_seccomp_rule_add:
    seccomp_release(ctx);

    return ret;
}
#endif
