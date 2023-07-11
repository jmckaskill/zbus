#define _GNU_SOURCE
#include "parse.h"
#include "message.h"
#include "stream.h"
#include "auth.h"
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <time.h>

#define ERR_FAILED 1
#define ERR_INVALID_ARG 5
#define MAX_CONTROL_SIZE 256
#define MAX_DGRAM_MESSAGES 8

void log_message(const struct msg_header *h, const struct msg_fields *f, const char *src) {
    fprintf(stderr, "have message source %s from %s to %s obj %s iface %s member %s sig %s\n",
        src,
        f->sender.p,
        f->destination.p,
        f->path.p,
        f->interface.p,
        f->member.p,
        f->signature.p);
}

static int usage(const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    fprintf(stderr, format, ap);
    va_end(ap);
    fputs("usage: sockbus-dbus-proxy [-v] [--] path/to/sockdir busid < recv > send\n", stderr);
    return ERR_INVALID_ARG;
}

int main(int argc, char *argv[]) {
    long verbose = 0;
    for (;;) {
        int i = getopt(argc, argv, "v");
        if (i < 0) {
            break;
        }
        switch (i) {
        case 'v':
            verbose = 1;
            break;
        case '?':
            return usage("");
        }
    }

    argc -= optind;
    argv += optind;

    if (argc != 2) {
        return usage("missing arguments\n");
    }

    char *busdir = argv[0];
    char *busid = argv[1];

    // buffer used for read call from stdin
    struct stream_buffer inbuf = INIT_STREAM_BUFFER;

    // enable SIGPIPE, and blocking on stdin/out for the auth call
    signal(SIGPIPE, SIG_DFL);
    fcntl(STDIN_FILENO, F_SETFL, 0);
    fcntl(STDOUT_FILENO, F_SETFL, 0);

    if (perform_auth(STDIN_FILENO, STDOUT_FILENO, &inbuf, busid)) {
        return ERR_FAILED;
    }

    realign_buffer(&inbuf);

    // set stdin to non block and ignore SIGPIPE
    // we'll deal with these synchronously in the write calls
    signal(SIGPIPE, SIG_IGN);
    fcntl(STDIN_FILENO, F_SETFL, (int)O_NONBLOCK);
    fcntl(STDOUT_FILENO, F_SETFL, 0);

    // we may have to auto-launch daemons. Don't want our stdin/out to leak
    fcntl(STDIN_FILENO, F_SETFD, FD_CLOEXEC);
    fcntl(STDOUT_FILENO, F_SETFD, FD_CLOEXEC);

    // lets setup and bind our unique address
    int bus = socket(AF_UNIX, SOCK_DGRAM, PF_UNIX);
    fcntl(bus, F_SETFL, (int)O_NONBLOCK);
    fcntl(bus, F_SETFD, (int)FD_CLOEXEC);

    srand(time(NULL));

    union {
        struct sockaddr sa;
        struct sockaddr_un sun;
    } addr;

    addr.sun.sun_family = AF_UNIX;
    
    // try a few times until we get an address
    for (int tries = 0;;tries++) {
        int n = snprintf(
            addr.sun.sun_path,
            sizeof(addr.sun.sun_path)-1,
            "%s/:%d.%d",
            busdir,
            getpid(),
            rand());
        if (n < 0 || n >= sizeof(addr.sun.sun_path)-1) {
            fprintf(stderr, "bus directory pathname %s is too long\n", busdir);
            return ERR_FAILED;
        }
        unlink(addr.sun.sun_path);
        if (!bind(bus, &addr.sa, offsetof(struct sockaddr_un, sun_path) + n + 1)) {
            break;
        }
        if (tries >= 10) {
            fprintf(stderr, "failed to bind unique address %s: %s\n", addr.sun.sun_path, strerror(errno));
            return ERR_FAILED;
        }
    }

    // buffers used for recvmmsg call from busdir
    struct iovec datav[MAX_DGRAM_MESSAGES];
    struct mmsghdr msgv[MAX_DGRAM_MESSAGES];
    char *controlv[MAX_DGRAM_MESSAGES];
    for (int i = 0; i < MAX_DGRAM_MESSAGES; i++) {
        datav[i].iov_len = MAX_MESSAGE_SIZE;
        datav[i].iov_base = malloc(MAX_MESSAGE_SIZE);
        controlv[i] = malloc(MAX_CONTROL_SIZE);
        if (!datav[i].iov_base || !controlv[i]) {
            perror("malloc failed");
            return ERR_FAILED;
        }
        struct msghdr *h = &msgv[i].msg_hdr;
        h->msg_iov = &datav[i];
        h->msg_iovlen = 1;
        h->msg_control = controlv[i];
        h->msg_controllen = MAX_CONTROL_SIZE;
        h->msg_flags = MSG_CMSG_CLOEXEC;
        h->msg_name = NULL;
        h->msg_namelen = 0;
    }

    struct pollfd pfd[2];
    pfd[0].fd = STDIN_FILENO;
    pfd[0].events = POLLIN;
    pfd[0].revents = POLLIN;
    pfd[1].fd = bus;
    pfd[1].events = POLLIN;
    pfd[1].revents = POLLIN;

    for (;;) {
        if (pfd[0].revents) {
            const struct msg_header *hdr;
            for (;;) {
                int sts = read_message(STDIN_FILENO, &inbuf, &hdr);
                if (sts == READ_ERROR) {
                    return ERR_FAILED;
                } else if (sts == READ_MORE) {
                    break;
                }
                // have a message
                struct msg_fields fields;
                if (parse_header_fields(&fields, hdr)) {
                    return ERR_FAILED;
                }
                if (verbose) {
                    log_message(hdr, &fields, "stdin");
                }
                drop_message(&inbuf);
            }
        }
        if (pfd[1].revents) {
            for (;;) {
                int msgnum = recvmmsg(bus, msgv, MAX_DGRAM_MESSAGES, 0, NULL);
                if (msgnum < 0 && (errno == EINTR || errno == EAGAIN)) {
                    break;
                } else if (msgnum < 0) {
                    // how does a unix datagram socket fail?
                    perror("recvmmsg");
                    return ERR_FAILED;
                }
                for (int i = 0; i < msgnum; i++) {
                    const struct msg_header *hdr = datav[i].iov_base;
                    int len = raw_message_length(hdr);
                    if (len < 0 || len > msgv[i].msg_len) {
                        // drop malformed messages
                        // TODO deal with unix fds
                        continue;
                    }
                    struct msg_fields fields;
                    if (parse_header_fields(&fields, hdr)) {
                        continue;
                    }
                    if (verbose) {
                        log_message(hdr, &fields, "busdir");
                    }
                }
            }
        }

        if (poll(pfd, 2, -1) <= 0) {
            perror("poll");
            return ERR_FAILED;
        }
    }
}
