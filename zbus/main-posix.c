#include "config.h"

#ifndef _WIN32
#define _GNU_SOURCE
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

#ifdef HAVE_ACCEPT4
#define x_accept4 accept4
#endif

static atomic_flag g_sighup;

static inline bool have_sighup(void)
{
	return !atomic_flag_test_and_set(&g_sighup);
}

static void on_sighup(int)
{
	atomic_flag_clear(&g_sighup);
}

#ifdef HAVE_AUTOLAUNCH
static atomic_flag g_sigchld;

static inline bool have_sigchld(void)
{
	return !atomic_flag_test_and_set(&g_sigchld);
}

static void on_sigchld(int)
{
	atomic_flag_clear(&g_sigchld);
}
#endif

#define CANCEL_SIGNAL (SIGRTMIN)

static void default_sigmask(sigset_t *ss)
{
	sigemptyset(ss);
#ifdef HAVE_AUTOLAUNCH
	sigaddset(ss, SIGCHLD);
#endif
	sigaddset(ss, SIGHUP);
	sigaddset(ss, CANCEL_SIGNAL);
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

#ifdef HAVE_AUTOLAUNCH
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

	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, NULL)) {
		ERROR("setup SIGPIPE,errno:%m");
		return -1;
	}

	setup_cancel(CANCEL_SIGNAL);

	return 0;
}

#ifdef HAVE_AUTOLAUNCH
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

int sys_launch(struct bus *bus, const str8_t *name)
{
	pid_t pid = fork();
	if (pid < 0) {
		ERROR("fork,errno:%m");
		return -1;
	}

	if (pid) {
		// parent
		struct child_info *c = fmalloc(sizeof(*c) + name->len);
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
#endif

static int ready_indicator(void *udata)
{
	str8_t *fifopn = udata;

	for (;;) {
		// Wait for a client to open the fifo for read. We then
		// immediately close it to indicate that we are ready to go
		int fd = open(fifopn->p, O_WRONLY | O_CLOEXEC);
		if (fd < 0) {
			ERROR("open ready fifo,error:%m,path:%s", fifopn->p);
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
	memset(&args, 0, sizeof(args));

	int i;
	while ((i = getopt(argc, argv, "hf:c:")) > 0 &&
	       args.num < MAX_ARGUMENTS) {
		switch (i) {
		case 'f':
			args.v[args.num++].file = optarg;
			break;
		case 'c':
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

	struct bus b;
	if (setup_signals() || init_bus(&b) || load_config(&b, &args)) {
		return 1;
	}

	const struct rcu_data *d = rcu_root(b.rcu);
	const struct config *c = d->config;

	if (!c->sockpn && c->sockfd < 0) {
		FATAL("no socket specified in config");
	}

	VERBOSE("startup,listen:%s,listenfd:%d,busid:%s", c->sockpn->p,
		c->sockfd, b.busid.p);

	int lfd = c->sockfd >= 0 ? c->sockfd : bind_bus(c->sockpn->p);
	if (lfd < 0) {
		return 1;
	}

	VERBOSE("ready");

	if (c->readypn) {
		VERBOSE("starting ready fifo thread,file:%s", c->readypn->p);
		thrd_t thrd;
		if (!thrd_create(&thrd, &ready_indicator,
				 str8dup(c->readypn))) {
			thrd_detach(thrd);
		}
	}

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
#ifdef HAVE_AUTOLAUNCH
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
#endif
