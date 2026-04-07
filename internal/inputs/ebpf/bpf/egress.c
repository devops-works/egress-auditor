// SPDX-License-Identifier: GPL-2.0
//
// egress.c — eBPF program capturing outgoing TCP/UDP connections.
//
// Hook points:
//   - kprobe/kretprobe tcp_v4_connect
//   - kprobe/kretprobe tcp_v6_connect
//   - kprobe udp_sendmsg
//   - kprobe udpv6_sendmsg
//
// Each successful connect emits an `event` to the perf event array. The
// kretprobe pattern is needed for tcp_*_connect because the destination
// port/address are populated on the sock struct *during* the call.
//
// Build: this file is compiled by `bpf2go` from the Go side; the toolchain
// requires clang and libbpf headers.

//go:build ignore

#include "vmlinux.h"

// bpf_tracing.h needs to know the host arch for PT_REGS_* macros. clang is
// invoked with -target bpf which doesn't set __x86_64__ / __aarch64__, so
// pick one explicitly. Override via -D__TARGET_ARCH_<arch> when building on
// non-x86 hosts.
#if !defined(__TARGET_ARCH_x86) && !defined(__TARGET_ARCH_arm64) && \
    !defined(__TARGET_ARCH_arm) && !defined(__TARGET_ARCH_powerpc) && \
    !defined(__TARGET_ARCH_s390) && !defined(__TARGET_ARCH_riscv)
#define __TARGET_ARCH_x86
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

#define AF_INET  2
#define AF_INET6 10

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct event {
    __u32 pid;
    __u8  saddr[4];
    __u8  daddr[4];
    __u8  saddr6[16];
    __u8  daddr6[16];
    __u16 sport;
    __u16 dport;
    __u8  ip_version;
    __u8  protocol;
    char  comm[16];
};

// Force emit type into BTF so bpf2go generates a Go mirror.
const struct event *unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Stash sock pointer between kprobe/kretprobe of tcp_*_connect, keyed by
// pid_tgid so concurrent connects from different threads don't collide.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct sock *);
} sock_store SEC(".maps");

static __always_inline void fill_common(struct event *evt, struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = pid_tgid >> 32;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    __u16 dport = 0;
    __u16 sport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    evt->dport = bpf_ntohs(dport);
    evt->sport = sport;
}

// ---------- TCP v4 ----------

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe_tcp_v4_connect, struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&sock_store, &pid_tgid, &sk, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(kretprobe_tcp_v4_connect, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skp = bpf_map_lookup_elem(&sock_store, &pid_tgid);
    if (!skp)
        return 0;

    if (ret != 0)
        goto cleanup;

    struct sock *sk = *skp;
    struct event evt = {};
    evt.ip_version = 4;
    evt.protocol = IPPROTO_TCP;

    bpf_probe_read_kernel(&evt.saddr, sizeof(evt.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&evt.daddr, sizeof(evt.daddr), &sk->__sk_common.skc_daddr);
    fill_common(&evt, sk);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

cleanup:
    bpf_map_delete_elem(&sock_store, &pid_tgid);
    return 0;
}

// ---------- TCP v6 ----------

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(kprobe_tcp_v6_connect, struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&sock_store, &pid_tgid, &sk, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(kretprobe_tcp_v6_connect, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skp = bpf_map_lookup_elem(&sock_store, &pid_tgid);
    if (!skp)
        return 0;

    if (ret != 0)
        goto cleanup;

    struct sock *sk = *skp;
    struct event evt = {};
    evt.ip_version = 6;
    evt.protocol = IPPROTO_TCP;

    bpf_probe_read_kernel(&evt.saddr6, sizeof(evt.saddr6),
                          &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    bpf_probe_read_kernel(&evt.daddr6, sizeof(evt.daddr6),
                          &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
    fill_common(&evt, sk);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

cleanup:
    bpf_map_delete_elem(&sock_store, &pid_tgid);
    return 0;
}

// ---------- UDP v4 ----------

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe_udp_sendmsg, struct sock *sk, struct msghdr *msg)
{
    struct event evt = {};
    evt.ip_version = 4;
    evt.protocol = IPPROTO_UDP;

    bpf_probe_read_kernel(&evt.saddr, sizeof(evt.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&evt.daddr, sizeof(evt.daddr), &sk->__sk_common.skc_daddr);
    fill_common(&evt, sk);

    // For unconnected UDP (sendto), daddr/dport are zero on the sock —
    // pull them from msghdr->msg_name (struct sockaddr_in *).
    if (evt.dport == 0) {
        struct sockaddr_in *sin = NULL;
        bpf_probe_read_kernel(&sin, sizeof(sin), &msg->msg_name);
        if (sin) {
            __u16 port = 0;
            bpf_probe_read_kernel(&evt.daddr, sizeof(evt.daddr), &sin->sin_addr.s_addr);
            bpf_probe_read_kernel(&port, sizeof(port), &sin->sin_port);
            evt.dport = bpf_ntohs(port);
        }
    }

    if (evt.dport == 0)
        return 0;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

// ---------- UDP v6 ----------

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(kprobe_udpv6_sendmsg, struct sock *sk, struct msghdr *msg)
{
    struct event evt = {};
    evt.ip_version = 6;
    evt.protocol = IPPROTO_UDP;

    bpf_probe_read_kernel(&evt.saddr6, sizeof(evt.saddr6),
                          &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    bpf_probe_read_kernel(&evt.daddr6, sizeof(evt.daddr6),
                          &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
    fill_common(&evt, sk);

    if (evt.dport == 0) {
        struct sockaddr_in6 *sin6 = NULL;
        bpf_probe_read_kernel(&sin6, sizeof(sin6), &msg->msg_name);
        if (sin6) {
            __u16 port = 0;
            bpf_probe_read_kernel(&evt.daddr6, sizeof(evt.daddr6),
                                  &sin6->sin6_addr.in6_u.u6_addr8);
            bpf_probe_read_kernel(&port, sizeof(port), &sin6->sin6_port);
            evt.dport = bpf_ntohs(port);
        }
    }

    if (evt.dport == 0)
        return 0;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}
