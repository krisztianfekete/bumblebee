// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define ARGSIZE  128
#define TASK_COMM_LEN 16
#define TOTAL_MAX_ARGS 60
#define DEFAULT_MAXARGS 20
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define INVALID_UID ((uid_t)-1)
#define BASE_EVENT_SIZE (size_t)(&((struct event*)0)->args)
#define EVENT_SIZE(e) (BASE_EVENT_SIZE + e->args_size)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

struct event {
        pid_t pid;
        pid_t ppid;
        uid_t uid;
        int retval;
        int args_count;
        unsigned int args_size;
        char comm[TASK_COMM_LEN];
        char args[FULL_MAX_ARGS_ARR];
};

const volatile bool filter_cg = false;
const volatile bool ignore_failed = true;
const volatile uid_t targ_uid = INVALID_UID;
const volatile int max_args = DEFAULT_MAXARGS;

static const struct event empty_event = {};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 10240);
        __type(key, pid_t);
        __type(value, struct event);
} execs SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 << 24);
        __type(value, struct event);
} events SEC(".maps.print");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
        u64 id;
        pid_t pid, tgid;
        unsigned int ret;
        struct event *event;
        struct task_struct *task;
        const char **args = (const char **)(ctx->args[1]);
        const char *argp;

        uid_t uid = (u32)bpf_get_current_uid_gid();
        int i;

        id = bpf_get_current_pid_tgid();
        pid = (pid_t)id;
        tgid = id >> 32;
        if (bpf_map_update_elem(&execs, &pid, &empty_event, BPF_NOEXIST))
                return 0;

        event = bpf_map_lookup_elem(&execs, &pid);
        if (!event)
                return 0;

        event->pid = tgid;
        event->uid = uid;
        task = (struct task_struct*)bpf_get_current_task();
        event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
        event->args_count = 0;
        event->args_size = 0;

        bpf_printk("enter: setting ctx for id: %u", id);


        ret = bpf_probe_read_user_str(event->args, ARGSIZE, (const char*)ctx->args[0]);
        if (ret <= ARGSIZE) {
                event->args_size += ret;
        } else {
                /* write an empty string */
                event->args[0] = '\0';
                event->args_size++;
        }

        bpf_printk("enter: setting ctx for args: %s", event->args);

        event->args_count++;
        #pragma unroll
        for (i = 1; i < TOTAL_MAX_ARGS && i < max_args; i++) {
                bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
                if (!argp)
                        return 0;

                if (event->args_size > LAST_ARG)
                        return 0;

                ret = bpf_probe_read_user_str(&event->args[event->args_size], ARGSIZE, argp);
                if (ret > ARGSIZE)
                        return 0;

                event->args_count++;
                event->args_size += ret;
        }

        /* try to read one more argument to check if there is one */
        bpf_probe_read_user(&argp, sizeof(argp), &args[max_args]);
        if (!argp)
                return 0;

        /* pointer to max_args+1 isn't null, asume we have more arguments */
        event->args_count++;

        return 0;
}


SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit* ctx)
{
        u64 id;
        pid_t pid;
        int ret;
        struct event *event;

        u32 uid = (u32)bpf_get_current_uid_gid();

        id = bpf_get_current_pid_tgid();
        pid = (pid_t)id;
        event = bpf_map_lookup_elem(&execs, &pid);

        event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);

        if (!event)
                return 0;
        ret = ctx->ret;
        event->retval = ret;
        bpf_get_current_comm(&event->comm, sizeof(event->comm));

        // Should not be needed here
        event->pid = pid;

        bpf_printk("exit: setting ctx for tid: %u", id);
        bpf_printk("exit: setting ctx for args: %s", event->args);

        /* submit event to ringbuf for printing */
        bpf_ringbuf_submit(event, 0);

        bpf_map_delete_elem(&execs, &pid);
        return 0;
}

char LICENSE[] SEC("license") = "GPL";
