/* The same echo server after following qnx-port-check's fixes.
 * Builds on Linux and on QNX 8.0. Portable core: poll(). QNX-native parts:
 * heartbeat timer delivered as a pulse, CPU runmask, system page CPU count. */
#define _GNU_SOURCE
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#if defined(__QNX__)
#include <sys/neutrino.h>
#include <sys/siginfo.h>
#define PULSE_HEARTBEAT (_PULSE_CODE_MINAVAIL + 1)
#else
#include <sched.h>
#include <sys/timerfd.h>
#endif

static int count_cpus(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);   /* works on both; no /proc/cpuinfo */
    return n > 0 ? (int)n : 1;
}

static void pin_to_cpu(int cpu) {
#if defined(__QNX__)
    /* QNX: a runmask bit per CPU, applied to the calling thread */
    if (cpu < 32 && ThreadCtl(_NTO_TCTL_RUNMASK, (void *)(uintptr_t)(1u << cpu)) == -1)
        perror("ThreadCtl(_NTO_TCTL_RUNMASK)");
#else
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof set, &set);
#endif
}

static unsigned long beats;

#if defined(__QNX__)
/* Heartbeat thread: the kernel delivers a pulse to our channel every second. */
static void *heartbeat(void *arg) {
    (void)arg;
    int chid = ChannelCreate(0);
    int coid = ConnectAttach(0, 0, chid, _NTO_SIDE_CHANNEL, 0);
    struct sigevent ev;
    SIGEV_PULSE_INIT(&ev, coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_HEARTBEAT, 0);
    timer_t t;
    timer_create(CLOCK_MONOTONIC, &ev, &t);
    struct itimerspec its = {{1, 0}, {1, 0}};
    timer_settime(t, 0, &its, NULL);
    for (;;) {
        struct _pulse p;
        if (MsgReceivePulse(chid, &p, sizeof p, NULL) == 0 && p.code == PULSE_HEARTBEAT) {
            printf("heartbeat %lu\n", ++beats);
            fflush(stdout);
        }
    }
    return NULL;
}
#endif

int main(void) {
    pthread_setname_np(pthread_self(), "echo-server");
    pin_to_cpu(count_cpus() - 1);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(7000);
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(srv, (struct sockaddr *)&a, sizeof a) || listen(srv, 16)) { perror("bind/listen"); return 1; }

    struct pollfd fds[2] = {{.fd = srv, .events = POLLIN}, {.fd = -1}};
#if defined(__QNX__)
    pthread_t hb;
    pthread_create(&hb, NULL, heartbeat, NULL);
#else
    int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec its = {{1, 0}, {1, 0}};
    timerfd_settime(tfd, 0, &its, NULL);
    fds[1].fd = tfd;
    fds[1].events = POLLIN;
#endif

    for (;;) {
        if (poll(fds, 2, -1) <= 0) continue;
#if !defined(__QNX__)
        if (fds[1].revents & POLLIN) {
            unsigned long long exp;
            if (read(fds[1].fd, &exp, sizeof exp) > 0) printf("heartbeat %lu\n", ++beats);
            fflush(stdout);
        }
#endif
        if (fds[0].revents & POLLIN) {
            int c = accept(srv, NULL, NULL);
            char buf[512];
            ssize_t r = read(c, buf, sizeof buf);
            if (r > 0) write(c, buf, (size_t)r);
            close(c);
        }
    }
}
