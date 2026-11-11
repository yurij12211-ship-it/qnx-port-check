/* A typical Linux daemon: TCP echo server with a 1 s heartbeat timer.
 * Written the "Linux way": epoll, timerfd, prctl, sched_setaffinity, /proc/cpuinfo.
 * This is the starting point of docs/codelab.md. */
#define _GNU_SOURCE
#include <netinet/in.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

static int count_cpus(void) {
    FILE *f = fopen("/proc/cpuinfo", "r");
    char line[256];
    int n = 0;
    if (!f) return 1;
    while (fgets(line, sizeof line, f))
        if (strncmp(line, "processor", 9) == 0) n++;
    fclose(f);
    return n ? n : 1;
}

int main(void) {
    prctl(PR_SET_NAME, "echo-server");

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(count_cpus() - 1, &set);          /* pin to the last CPU */
    sched_setaffinity(0, sizeof set, &set);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(7000), .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (bind(srv, (struct sockaddr *)&a, sizeof a) || listen(srv, 16)) { perror("bind/listen"); return 1; }

    int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec its = {{1, 0}, {1, 0}};
    timerfd_settime(tfd, 0, &its, NULL);

    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN};
    ev.data.fd = srv; epoll_ctl(ep, EPOLL_CTL_ADD, srv, &ev);
    ev.data.fd = tfd; epoll_ctl(ep, EPOLL_CTL_ADD, tfd, &ev);

    unsigned long beats = 0;
    for (;;) {
        struct epoll_event out[8];
        int n = epoll_wait(ep, out, 8, -1);
        for (int i = 0; i < n; i++) {
            if (out[i].data.fd == tfd) {
                unsigned long long exp;
                read(tfd, &exp, sizeof exp);
                printf("heartbeat %lu\n", ++beats);
                fflush(stdout);
            } else {
                int c = accept(srv, NULL, NULL);
                char buf[512];
                ssize_t r = read(c, buf, sizeof buf);
                if (r > 0) write(c, buf, (size_t)r);
                close(c);
            }
        }
    }
}
