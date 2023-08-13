#define _GNU_SOURCE
#include "config.h"
#include "tx.h"
#include "rx.h"
#include "bus.h"
#include "config.h"
#include "lib/log.h"
#include <signal.h>
#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <threads.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <poll.h>
#include <errno.h>
#include <spawn.h>

#if HAVE_ACCEPT4
#define x_accept4 accept4
#endif

static atomic_flag g_sighup;

static inline bool have_sighup(void)
{
	return !atomic_flag_test_and_set(&g_sighup);
}

static void on_sighup(int sig)
{
	atomic_flag_clear(&g_sighup);
}

#if ENABLE_AUTOSTART
static atomic_flag g_sigchld;

static inline bool have_sigchld(void)
{
	return !atomic_flag_test_and_set(&g_sigchld);
}

static void on_sigchld(int sig)
{
	atomic_flag_clear(&g_sigchld);
}
#endif

#define CANCEL_SIGNAL (SIGRTMIN)

static void default_sigmask(sigset_t *ss)
{
	sigemptyset(ss);
#if ENABLE_AUTOSTART
	sigaddset(ss, SIGCHLD);
#endif
	sigaddset(ss, SIGHUP);
	sigaddset(ss, CANCEL_SIGNAL);
	sigaddset(ss, SIGPIPE);
}

int setup_signals(void)
{
	// set default mask
	sigset_t mask;
	default_sigmask(&mask);
	if (pthread_sigmask(SIG_SETMASK, &mask, NULL)) {
		ERROR("set default sigmask,errno:%m");
		return -1;
	}

	// setup handlers
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));

#if ENABLE_AUTOSTART
	atomic_flag_test_and_set(&g_sigchld);
	sa.sa_handler = &on_sigchld;
	if (sigaction(SIGCHLD, &sa, NULL)) {
		ERROR("setup sigchld,errno:%m");
		return -1;
	}
#endif

	atomic_flag_test_and_set(&g_sighup);
	sa.sa_handler = &on_sighup;
	if (sigaction(SIGHUP, &sa, NULL)) {
		ERROR("setup sighup,errno:%m");
		return -1;
	}

	setup_cancel(CANCEL_SIGNAL);

	return 0;
}

#if ENABLE_AUTOSTART
struct child_info {
	struct bus *bus;
	pid_t pid;
	str8_t name;
};

KHASH_MAP_INIT_INT(child_info, struct child_info *)

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

int sys_launch(struct bus *b, const struct address *a)
{
	const struct rcu_data *d = rcu_root(b->rcu);
	if (d->config->type) {
		setenv("DBUS_STARTER_BUS_TYPE", d->config->type, 1);
	}
	if (d->config->address) {
		setenv("DBUS_STARTER_ADDRESS", d->config->address, 1);
	}

	posix_spawnattr_t attr;
	posix_spawnattr_init(&attr);

	// clear the signal mask in the child
	// signal handlers are always reset to defaults on exec
	sigset_t mask;
	sigemptyset(&mask);
	posix_spawnattr_setsigmask(&attr, &mask);

	pid_t pid;
	char *args[] = {
		"/bin/sh", "sh", "-c", a->cfg->exec, NULL,
	};
	posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK);
	int err = posix_spawn(&pid, "/bin/sh", NULL, &attr, args, environ);
	posix_spawnattr_destroy(&attr);

	if (err) {
		ERROR("spawn,errno:%m,name:%s,exec:%s", a->name.p,
		      a->cfg->exec);
	} else {
		struct child_info *c = fmalloc(sizeof(*c) + a->name.len);
		str8cpy(&c->name, &a->name);
		c->bus = b;
		c->pid = pid;

		mtx_lock(&child_lk);
		int sts;
		khint_t ii = kh_put(child_info, &children, pid, &sts);
		if (!sts) {
			free(kh_val(&children, ii));
		}
		kh_val(&children, ii) = c;
		mtx_unlock(&child_lk);
	}

	return err;
}
#endif

static int ready_indicator(void *udata)
{
	char *fifopn = udata;

	for (;;) {
		// Wait for a client to open the fifo for read. We then
		// immediately close it to indicate that we are ready to go
		int fd = open(fifopn, O_WRONLY | O_CLOEXEC);
		if (fd < 0) {
			ERROR("open ready fifo,error:%m,path:%s", fifopn);
			free(fifopn);
			return -1;
		}
		DEBUG("open ready fifo");
		close(fd);
		usleep(1000);
	}
}

int bind_bus(const char *sockpn)
{
	int lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
			 PF_UNIX);
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

static int usage(void)
{
	fputs("usage: zbus [args]\n", stderr);
	fputs("\t-f config\tLoad config file\n", stderr);
	fputs("\t-c 'foo=bar'\tLoad config item\n", stderr);
	return 2;
}

int main(int argc, char *argv[])
{
	struct config_arguments args;
	args.num = 0;

	int i;
	while ((i = getopt(argc, argv, "hf:c:")) > 0 &&
	       args.num < MAX_ARGUMENTS) {
		switch (i) {
		case 'f':
			args.v[args.num].cmdline = NULL;
			args.v[args.num++].file = optarg;
			break;
		case 'c':
			args.v[args.num].file = NULL;
			args.v[args.num++].cmdline = optarg;
			break;
		case 'h':
		case '?':
			return usage();
		}
	}

	if (argc - optind) {
		fputs("unexpected arguments\n", stderr);
		return usage();
	}

	LOG("bufsz,sz:%zu,sigsz:%zu,rxsz:%zu,txsz:%zu,bussz:%zu",
	    (size_t)NAME_OWNER_CHANGED_BUFSZ, (size_t)SIGNAL_HDR_BUFSZ,
	    sizeof(struct rx), sizeof(struct tx), sizeof(struct bus));

	struct bus b;
	if (setup_signals() || init_bus(&b) || load_config(&b, &args)) {
		return 1;
	}

	const struct rcu_data *d = rcu_root(b.rcu);
	const struct config *c = d->config;

	if (!c->listenpn && c->listenfd < 0) {
		FATAL("no socket specified in config");
	}

	VERBOSE("startup,listen:%s,listenfd:%d,busid:%s", c->listenpn,
		c->listenfd, b.busid.p);

	int lfd = c->listenfd >= 0 ? c->listenfd : bind_bus(c->listenpn);
	if (lfd < 0) {
		return 1;
	}

	VERBOSE("ready");

	if (c->readypn) {
		VERBOSE("starting ready fifo thread,file:%s", c->readypn);
		thrd_t thrd;
		if (!thrd_create(&thrd, &ready_indicator, strdup(c->readypn))) {
			thrd_detach(thrd);
		}
	}

	if (lfd != 0) {
		close(0);
	}

	g_enable_security = true;
	int next_id = 1;

	for (;;) {
		// accept a single connection
		int cfd = x_accept4(lfd, NULL, NULL,
				    SOCK_CLOEXEC | SOCK_NONBLOCK);
		if (cfd < 0 && (errno != EAGAIN && errno != EINTR)) {
			ERROR("accept,errno:%m");
			return 2;
		} else if (cfd >= 0) {
			VERBOSE("new connection,fd:%d", cfd);

			struct rx *rx = new_rx(&b, next_id++);
			rx->tx->conn.fd = cfd;
			rx->conn.fd = cfd;

			thrd_t thrd;
			if (thrd_create(&thrd, (thrd_start_t)&run_rx, rx) ==
			    thrd_success) {
				thrd_detach(thrd);
			} else {
				ERROR("failed to create rx thread");
				free_rx(rx);
			}
		}

		// check our signals
		struct pollfd pfd = {
			.fd = lfd,
			.events = POLLIN,
		};
		sigset_t ss;
		default_sigmask(&ss);
		sigdelset(&ss, SIGCHLD);
		sigdelset(&ss, SIGHUP);
		int n = ppoll(&pfd, 1, NULL, &ss);
		if (n == 1) {
			continue;
#if ENABLE_AUTOSTART
		} else if (have_sigchld() && reap_children()) {
			return 1;
#endif
		} else if (have_sighup()) {
			mtx_lock(&b.lk);
			if (load_config(&b, &args)) {
				ERROR("failed to reload config - continuing with previous config");
			}
			mtx_unlock(&b.lk);
			continue;
		} else if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
			continue;
		} else {
			ERROR("poll,errno:%m");
			return 1;
		}
	}
}
