#define _GNU_SOURCE
#include "sys.h"
#include "bus.h"
#include "lib/log.h"
#include "lib/algo.h"
#include "vendor/klib-master/khash.h"
#include <errno.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#include <threads.h>
#include <stdatomic.h>
#include <dirent.h>
#include <sys/types.h>

int generate_busid(str8_t *s)
{
	static const char hex_enc[] = "0123456789abcdef";
	uint8_t rand[16];
	if (getentropy(rand, sizeof(rand))) {
		ERROR("getentropy,errno:%m");
		return -1;
	}
	for (int i = 0; i < sizeof(rand); i++) {
		s->p[2 * i] = hex_enc[rand[i] >> 4];
		s->p[2 * i + 1] = hex_enc[rand[i] & 15];
	}
	size_t n = 2 * sizeof(rand);
	s->len = n;
	s->p[n] = 0;
	return 0;
}

int bind_bus(const char *sockpn)
{
	int lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, PF_UNIX);
	if (lfd < 0) {
		ERROR("socket,errno:%m");
		goto error;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	size_t pnlen = strlen(sockpn);
	if (pnlen + 1 > sizeof(addr.sun_path)) {
		ERROR("socket pathname too long,path:%s", sockpn);
		goto error;
	}

	unlink(sockpn);

	memcpy(addr.sun_path, sockpn, pnlen + 1);

	socklen_t salen = addr.sun_path + pnlen + 1 - (char *)&addr;
	if (bind(lfd, (struct sockaddr *)&addr, salen) ||
	    listen(lfd, SOMAXCONN)) {
		ERROR("bind,errno:%m,path:%s", sockpn);
		goto error;
	}

	return lfd;
error:
	close(lfd);
	return -1;
}

static atomic_flag g_sighup;
static atomic_flag g_sigchld;

static inline bool have_sighup(void)
{
	return !atomic_flag_test_and_set(&g_sighup);
}

static inline bool have_sigchld(void)
{
	return !atomic_flag_test_and_set(&g_sigchld);
}

static void on_sighup(int)
{
	atomic_flag_clear(&g_sighup);
}

static void on_sigchld(int)
{
	atomic_flag_clear(&g_sigchld);
}

struct child_info {
	struct bus *bus;
	pid_t pid;
	str8_t name;
};

KHASH_MAP_INIT_INT(child_info, struct child_info *);

static mtx_t child_lk;
static khash_t(child_info) children;

static int reap_children(void)
{
	for (;;) {
		int sts;
		pid_t pid = waitpid(-1, &sts, WNOHANG);

		if (pid < 0 && (errno == EAGAIN || errno == ECHILD)) {
			return 0;
		} else if (pid < 0) {
			ERROR("wait failed,errno:%m");
			return -1;
		}

		mtx_lock(&child_lk);
		khint_t ii = kh_get(child_info, &children, pid);
		if (ii == kh_end(&children)) {
			ERROR("unknown child exited,pid:%d", pid);
			mtx_unlock(&child_lk);
			continue;
		}

		struct child_info *c = kh_val(&children, ii);

		if (WIFSIGNALED(sts)) {
			ERROR("child exited with signal,pid:%d,signal:%d,name:%.*s",
			      pid, WTERMSIG(sts), c->name.len, c->name.p);
		} else if (WIFEXITED(sts) && WEXITSTATUS(sts)) {
			ERROR("child exited with error,pid:%d,code:%d,name:%.*s",
			      pid, WEXITSTATUS(sts), c->name.len, c->name.p);
		} else if (WIFEXITED(sts)) {
			LOG("child exited,pid:%d,name:%.*s", pid, c->name.len,
			    c->name.p);
		}

		kh_del(child_info, &children, ii);
		mtx_unlock(&child_lk);

		mtx_lock(&c->bus->lk);
		service_exited(c->bus, &c->name);
		mtx_unlock(&c->bus->lk);

		free(c);
	}

	return 0;
}

int launch_service(struct bus *bus, const str8_t *name)
{
	pid_t pid = fork();
	if (pid < 0) {
		ERROR("fork,errno:%m");
		return -1;
	}

	if (pid) {
		// parent
		struct child_info *c = malloc(sizeof(*c) + name->len);
		if (!c) {
			return -1;
		}

		str8cpy(&c->name, name);
		c->bus = bus;
		c->pid = pid;

		mtx_lock(&child_lk);
		int sts;
		khint_t ii = kh_put(child_info, &children, pid, &sts);
		if (!sts) {
			free(kh_val(&children, ii));
		}
		kh_val(&children, ii) = c;
		mtx_unlock(&child_lk);
		return 0;
	} else {
		// child
		char *args[] = {
			"zbus-launch",
			(char *)name->p,
			NULL,
		};

		close(0);
		close(1);
		// leave stderr open

		sigset_t ss;
		sigemptyset(&ss);
		pthread_sigmask(SIG_SETMASK, &ss, NULL);

		execvp("zbus-launch", args);
		ERROR("execvp failed in child,errno:%m");
		exit(112);
	}
}

int setup_signals(void)
{
	// set default mask
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigaddset(&mask, SIGHUP);
	if (pthread_sigmask(SIG_SETMASK, &mask, NULL)) {
		ERROR("set sigmask,errno:%m");
		return -1;
	}

	atomic_flag_test_and_set(&g_sigchld);
	atomic_flag_test_and_set(&g_sighup);

	// setup handlers
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));

	sa.sa_handler = &on_sigchld;
	if (sigaction(SIGCHLD, &sa, NULL)) {
		ERROR("setup sigchld,errno:%m");
		return -1;
	}

	sa.sa_handler = &on_sighup;
	if (sigaction(SIGHUP, &sa, NULL)) {
		ERROR("setup sighup,errno:%m");
		return -1;
	}

	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, NULL)) {
		ERROR("setup SIGPIPE,errno:%m");
		return -1;
	}

	return 0;
}

void kill_services(void)
{
	mtx_lock(&child_lk);
	for (khint_t ii = kh_begin(&children); ii != kh_end(&children); ii++) {
		if (kh_exist(&children, ii)) {
			struct child_info *c = kh_val(&children, ii);
			kill(c->pid, SIGTERM);
		}
	}
	mtx_unlock(&child_lk);
}

void must_set_non_blocking(int fd)
{
	if (fcntl(fd, F_SETFL, O_NONBLOCK)) {
		FATAL("failed to set fd non-nonblocking,errno:%m");
	}
}

int poll_one(int fd, bool read, bool write)
{
try_again:
	struct pollfd pfd = {
		.fd = fd,
		.events = (read ? POLLIN : 0) | (write ? POLLOUT : 0),
	};
	int n = poll(&pfd, 1, -1);
	if (n < 0 && errno == EINTR) {
		goto try_again;
	}
	return n <= 0;
}

int poll_accept(int fd)
{
try_again:
	struct pollfd pfd = {
		.fd = fd,
		.events = POLLIN,
	};
	sigset_t ss;
	sigemptyset(&ss);
	int n = ppoll(&pfd, 1, NULL, &ss);
	if (n == 1) {
		return POLL_ACCEPT;
	} else if (have_sigchld() && reap_children()) {
		return -1;
	} else if (have_sighup()) {
		return POLL_SIGHUP;
	} else if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
		goto try_again;
	} else {
		ERROR("poll,errno:%m");
		return -1;
	}
}

#ifndef NDEBUG
void set_thread_name(const char *s)
{
	pthread_setname_np(pthread_self(), s);
}
#endif
