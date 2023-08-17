#define _GNU_SOURCE
#include "config.h"
#include "tx.h"
#include "rx.h"
#include "bus.h"
#include "config.h"
#include "lib/log.h"
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <threads.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <poll.h>
#include <errno.h>
#include <spawn.h>

static atomic_flag g_sighup;

static inline bool have_sighup(void)
{
	return !atomic_flag_test_and_set(&g_sighup);
}

static void on_sighup(int sig)
{
	atomic_flag_clear(&g_sighup);
}

#ifdef CAN_AUTOSTART
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
#ifdef CAN_AUTOSTART
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

#ifdef CAN_AUTOSTART
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

#ifdef CAN_AUTOSTART
struct child_info {
	struct bus *bus;
	pid_t pid;
	zb_str8 name;
};

KHASH_MAP_INIT_INT(child_info, struct child_info *)

static pthread_mutex_t g_children_lk = PTHREAD_MUTEX_INITIALIZER;
static khash_t(child_info) * g_children;

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

		pthread_mutex_lock(&g_children_lk);
		khint_t ii = kh_get(child_info, g_children, pid);
		if (ii == kh_end(g_children)) {
			ERROR("unknown child exited,pid:%d", pid);
			pthread_mutex_unlock(&g_children_lk);
			continue;
		}

		struct child_info *c = kh_val(g_children, ii);

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

		kh_del(child_info, g_children, ii);
		pthread_mutex_unlock(&g_children_lk);

		mtx_lock(&c->bus->lk);
		service_exited(c->bus, &c->name);
		mtx_unlock(&c->bus->lk);

		free(c);
	}

	return 0;
}

int sys_launch(struct bus *b, const struct address *a)
{
	posix_spawnattr_t attr;
	posix_spawnattr_init(&attr);

	// clear the signal mask in the child
	// signal handlers are always reset to defaults on exec
	sigset_t mask;
	sigemptyset(&mask);
	posix_spawnattr_setsigmask(&attr, &mask);

	pid_t pid;
	char *args[] = {
		"sh",
		"-c",
		a->cfg->exec,
		NULL,
	};
	posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK);

	pthread_mutex_lock(&g_children_lk);
	int err = posix_spawn(&pid, "/bin/sh", NULL, &attr, args, environ);
	posix_spawnattr_destroy(&attr);

	if (err) {
		ERROR("spawn,errno:%m,name:%s,exec:%s", a->name.p,
		      a->cfg->exec);
	} else {
		struct child_info *c = fmalloc(sizeof(*c) + a->name.len);
		zb_copy_str8(&c->name, &a->name);
		c->bus = b;
		c->pid = pid;

		int sts;
		khint_t ii = kh_put(child_info, g_children, pid, &sts);
		if (!sts) {
			free(kh_val(g_children, ii));
		}
		kh_val(g_children, ii) = c;
	}
	pthread_mutex_unlock(&g_children_lk);

	return err;
}
#endif

static void *ready_indicator(void *udata)
{
	char *fifopn = udata;

	for (;;) {
		// Wait for a client to open the fifo for read. We then
		// immediately close it to indicate that we are ready to go
		int fd = open(fifopn, O_WRONLY | O_CLOEXEC);
		if (fd < 0) {
			FATAL("open ready fifo,error:%m,path:%s", fifopn);
			return NULL;
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

static atomic_int g_rx_threads;

static int rx_thread(void *udata)
{
	struct rx *rx = udata;
	run_rx(rx);
	atomic_fetch_sub_explicit(&g_rx_threads, 1, memory_order_release);
	return 0;
}

static void start_rx_thread(struct bus *b, int fd, int id)
{
	struct rx *rx = new_rx(b, id);
	rx->tx->conn.fd = fd;
	rx->conn.fd = fd;

	atomic_fetch_add_explicit(&g_rx_threads, 1, memory_order_relaxed);

	thrd_t thrd;
	if (thrd_create(&thrd, &rx_thread, rx) == thrd_success) {
		thrd_detach(thrd);
	} else {
		atomic_fetch_sub_explicit(&g_rx_threads, 1,
					  memory_order_relaxed);
		ERROR("failed to create rx thread");
		free_rx(rx);
	}
}

static int check_autoexit(void)
{
	if (atomic_load_explicit(&g_rx_threads, memory_order_acquire) == 0) {
		return 1;
	}
	return 0;
}

struct main_thread {
	struct bus bus;
	bool autoexit;
	pthread_t ready_thrd;
	char *readypn;
};

static void do_setenv(const char *key, const char *value)
{
	if (value) {
		setenv(key, value, 1);
	} else {
		unsetenv(key);
	}
}

static void update_main_thread(struct main_thread *m)
{
	const struct rcu_data *d = rcu_root(m->bus.rcu);
#ifdef CAN_AUTOSTART
	do_setenv("DBUS_STARTER_BUS_TYPE", d->config->type);
	do_setenv("DBUS_STARTER_ADDRESS", d->config->address);
#endif
	m->autoexit = d->config->autoexit;
	if (m->readypn &&
	    (!d->config->readypn || strcmp(m->readypn, d->config->readypn))) {
		pthread_cancel(m->ready_thrd);
		pthread_join(m->ready_thrd, NULL);
		free(m->readypn);
		m->readypn = NULL;
	}
	if (d->config->readypn && !m->readypn) {
		m->readypn = strdup(d->config->readypn);
		VERBOSE("starting ready fifo thread,file:%s", m->readypn);
		if (pthread_create(&m->ready_thrd, NULL, &ready_indicator,
				   m->readypn)) {
			FATAL("failed to spawn ready indicator thread,errno:%m");
		}
	}
}

static int usage(void)
{
	fputs("usage: zbus [config] [--] [config-files]\n", stderr);
	fputs("\tCommand line config can be any of:\n", stderr);
	fputs("\t\t--key=value\n", stderr);
	fputs("\t\t--key value\n", stderr);
	fputs("\t\t-key=value\n", stderr);
	fputs("\t\t-key value\n", stderr);
	fputs("\tAny arguments not prefixed with '-' or after '--' will be treated as config files\n",
	      stderr);
	return 2;
}

int main(int argc, char *argv[])
{
	struct config_arguments args;
	args.num = 0;

	if (parse_argv(&args, argc, argv)) {
		return usage();
	}

	struct main_thread m;
	memset(&m, 0, sizeof(m));
	if (setup_signals() || init_bus(&m.bus) || load_config(&m.bus, &args)) {
		return 1;
	}

	const struct rcu_data *d = rcu_root(m.bus.rcu);
	const struct config *c = d->config;

	if (!c->listenpn && c->listenfd < 0) {
		FATAL("no socket specified in config");
	}

	VERBOSE("startup,listen:%s,listenfd:%d,busid:%s", c->listenpn,
		c->listenfd, m.bus.busid.p);

	int lfd = c->listenfd >= 0 ? c->listenfd : bind_bus(c->listenpn);
	if (lfd < 0) {
		return 1;
	}

	VERBOSE("ready");

	if (lfd != 0) {
		close(0);
	}

	update_main_thread(&m);
	int next_id = 1;

#ifdef CAN_AUTOSTART
	g_children = kh_init(child_info);
#endif

	for (;;) {
		// accept a single connection
#ifdef CAN_AUTOSTART
		int cfd =
			accept4(lfd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
#else
		// no need for cloexec when we don't launch child processes
		int cfd = accept(lfd, NULL, NULL);
		fcntl(cfd, F_SETFL, O_NONBLOCK);
#endif
		if (cfd < 0 && (errno != EAGAIN && errno != EINTR)) {
			ERROR("accept,errno:%m");
			return 2;
		} else if (cfd >= 0) {
			VERBOSE("new connection,fd:%d", cfd);
			start_rx_thread(&m.bus, cfd, next_id++);
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
		struct timespec exit_timeout;
		exit_timeout.tv_sec = 5;
		exit_timeout.tv_nsec = 0;
		int n = ppoll(&pfd, 1, m.autoexit ? &exit_timeout : NULL, &ss);
		if (n == 1) {
			continue;
#ifdef CAN_AUTOSTART
		} else if (have_sigchld()) {
			if (reap_children()) {
				return 1;
			}
#endif
		} else if (have_sighup()) {
			mtx_lock(&m.bus.lk);
			if (load_config(&m.bus, &args)) {
				ERROR("failed to reload config - continuing with previous config");
			}
			update_main_thread(&m);
			mtx_unlock(&m.bus.lk);
			continue;
		} else if (!n) {
			assert(m.autoexit);
			if (check_autoexit()) {
				break;
			}

		} else if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
			continue;
		} else {
			ERROR("poll,errno:%m");
			return 1;
		}
	}

	destroy_bus(&m.bus);
	if (m.readypn) {
		pthread_cancel(m.ready_thrd);
		pthread_join(m.ready_thrd, NULL);
		free(m.readypn);
	}
#ifdef CAN_AUTOSTART
	kh_destroy(child_info, g_children);
#endif
	return 0;
}
