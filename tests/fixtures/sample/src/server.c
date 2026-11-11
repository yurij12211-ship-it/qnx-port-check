/* Tiny Linux-style event server used as a test fixture. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sched.h>
#include <linux/if_packet.h>

// epoll_create1( in a comment must not be reported

static void pin_to_cpu0(void) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

int main(void) {
    prctl(PR_SET_NAME, "server");
    pin_to_cpu0();
    int ep = epoll_create1(0);
    int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    FILE *f = fopen("/proc/cpuinfo", "r");
    const char *msg = "epoll_wait( inside a string is code-like but harmless";
#ifdef __linux__
    puts("linux");
#endif
    (void)ep; (void)tfd; (void)s; (void)f; (void)msg;
    return 0;
}
