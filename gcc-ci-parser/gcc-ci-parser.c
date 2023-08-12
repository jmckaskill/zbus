#define _GNU_SOURCE
#include "lib/file.h"
#include "lib/log.h"
#include "lib/khash.h"
#include <stdio.h>
#include <string.h>
#include <getopt.h>

struct edge {
	struct edge *next;
	char *label;
	struct node *src;
	struct node *tgt;
};

struct node {
	char *title;
	char *name;
	char *loc;
	char *stack;
	int size;
	struct edge *edges;
};

KHASH_MAP_INIT_STR(node, struct node *);
static khash_t(node) * g_nodes;

static struct node *get_node(char *title)
{
	int res;
	khint_t idx = kh_put(node, g_nodes, title, &res);
	if (res) {
		struct node *n = calloc(1, sizeof(*n));
		kh_val(g_nodes, idx) = n;
	}
	return kh_val(g_nodes, idx);
}

static char *skip_space(char *p)
{
	while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
		p++;
	}
	return p;
}

static char *parse_token(char *p, char **pstr)
{
	if (pstr) {
		*pstr = p;
	}
	while ('a' <= *p && *p <= 'z') {
		p++;
	}
	*p = 0;
	return skip_space(p + 1);
}

static char *parse_string(char *p, char **pstr)
{
	if (*p != '"') {
		FATAL("expected open quote");
	}
	p++;
	if (pstr) {
		*pstr = p;
	}
	char *s = p;
	for (;;) {
		if (!*p) {
			FATAL("expected close quote");
		} else if (*p == '"') {
			*s = 0;
			return skip_space(p + 1);
		} else if (*p == '\\') {
			if (p[1] == 'n') {
				*s++ = '\n';
				p += 2;
			} else {
				FATAL("unexpected escape");
			}
		} else {
			*s++ = *p++;
		}
	}
}

static char *parse_key(char *p, char **pstr)
{
	if (pstr) {
		*pstr = p;
	}
	while ('a' <= *p && *p <= 'z') {
		p++;
	}
	char *end = p;
	p = skip_space(p);
	if (*p != ':') {
		FATAL("expected key colon");
	}
	*end = 0;
	return skip_space(p + 1);
}

static struct edge *find_edge(struct node *src, struct node *tgt)
{
	for (struct edge *e = src->edges; e != NULL; e = e->next) {
		if (e->tgt == tgt) {
			return e;
		}
	}
	return NULL;
}

static char *parse_edge(char *p)
{
	if (*p != '{') {
		FATAL("expected node to have a map");
	}
	char *src = NULL;
	char *tgt = NULL;
	char *label = NULL;
	p = skip_space(p + 1);
	while (*p != '}') {
		char *key;
		p = parse_key(p, &key);
		if (!strcmp(key, "sourcename")) {
			p = parse_string(p, &src);
		} else if (!strcmp(key, "targetname")) {
			p = parse_string(p, &tgt);
		} else if (!strcmp(key, "label")) {
			p = parse_string(p, &label);
		} else {
			FATAL("unexpected edge key,key:%s", key);
		}
	}
	struct node *s = get_node(src);
	struct node *t = get_node(tgt);
	struct edge *e = find_edge(s, t);
	if (!e) {
		e = calloc(1, sizeof(*e));
		e->label = label;
		e->tgt = t;
		e->src = s;
		e->next = s->edges;
		s->edges = e;
	}
	VERBOSE("visit edge,src:%s,tgt:%s,label:%s", src, tgt, label);
	return skip_space(p + 1);
}

static char *get_line(char **p)
{
	if (!**p) {
		return NULL;
	}
	char *ret = *p;
	char *nl = strchrnul(*p, '\n');
	if (*nl) {
		*nl = 0;
		*p = nl + 1;
	} else {
		*p = nl;
	}
	return ret;
}

static char *parse_node(char *p)
{
	if (*p != '{') {
		FATAL("expected node to have a map");
	}
	char *title = NULL;
	char *name = NULL;
	char *loc = NULL;
	char *stack = NULL;
	p = skip_space(p + 1);
	while (*p != '}') {
		char *key;
		p = parse_key(p, &key);
		if (!strcmp(key, "title")) {
			p = parse_string(p, &title);
		} else if (!strcmp(key, "label")) {
			char *label;
			p = parse_string(p, &label);
			name = get_line(&label);
			loc = get_line(&label);
			stack = get_line(&label);
		} else if (!strcmp(key, "shape")) {
			p = parse_token(p, NULL);
		} else {
			FATAL("unexpected node key,key:%s", key);
		}
	}
	struct node *n = get_node(title);
	n->title = title;
	n->name = name;
	if (stack) {
		n->loc = loc;
		n->stack = stack;
		n->size = atoi(stack);
	}
	VERBOSE("visit node,title:%s,name:%s,loc:%s,stack:%s", title, name, loc,
		stack);
	return skip_space(p + 1);
}

static char *parse_graph(char *p)
{
	if (*p != '{') {
		FATAL("expected graph to have a map");
	}
	p = skip_space(p + 1);
	while (*p != '}') {
		char *key;
		p = parse_key(p, &key);
		if (!strcmp(key, "node")) {
			p = parse_node(p);
		} else if (!strcmp(key, "edge")) {
			p = parse_edge(p);
		} else if (!strcmp(key, "title")) {
			char *title;
			p = parse_string(p, &title);
			VERBOSE("graph title,title:%s", title);
		} else {
			FATAL("unexpected graph component,key:%s", key);
		}
	}
	return skip_space(p + 1);
}

static void parse_file(const char *fn, char *buf, size_t sz)
{
	char *p = buf;
	if (memchr(buf, 0, sz)) {
		FATAL("embedded nul");
	}
	char *root;
	p = parse_key(p, &root);
	if (!strcmp(root, "graph")) {
		p = parse_graph(p);
	} else {
		FATAL("unexpected root key,key:%s,file:%s", root, fn);
	}
	if (*p) {
		FATAL("unexpected tail content,file:%s", fn);
	}
}

struct print_stack {
	struct edge *edge;
	int size;
	int max;
};

static void dump_stack(struct print_stack *s, struct print_stack *base)
{
	for (int i = 0; i < s - base; i++) {
		struct node *n = base[i].edge->tgt;
		LOG("stack entry,depth:%d,title:%s", i, n->title);
	}
}

static void print_stack(struct node *root)
{
	struct print_stack stack[64];
	struct print_stack *end = &stack[64];
	struct print_stack *s = &stack[0];

	fprintf(stdout, "%s %s %d\n", root->title, root->stack, root->size);

	s->edge = root->edges;
	s->size = root->size;
	s->max = root->size;

	for (;;) {
		struct edge *e = s->edge;
		if (!e) {
			if (s == stack) {
				break;
			}
			// pop an item off the stack
			int max = s->max;
			s--;
			e = s->edge;
			for (int depth = s - stack; depth >= 0; depth--) {
				fputc('\t', stdout);
			}
			struct node *t = e->tgt;
			int parent = s->size;
			int tgtsize = t->size;
			int children = max - parent - tgtsize;
			fprintf(stdout, "%d +%d C+%d\n", max, tgtsize,
				children);
			s->edge = e->next;
			if (max > s->max) {
				s->max = max;
			}
		} else {
			for (int depth = s - stack; depth >= 0; depth--) {
				fputc('\t', stdout);
			}
			struct node *t = e->tgt;
			int size = s->size + t->size;

			if (size > s->max) {
				s->max = size;
			}
			fprintf(stdout, "%d +%d %s\n", size, t->size,
				t->title);

			if (s == end) {
				dump_stack(s, stack);
				FATAL("stack overflow");
			} else if (t->edges) {
				s++;
				s->edge = t->edges;
				s->max = size;
				s->size = size;
			} else {
				s->edge = e->next;
			}
		}
	}
	fprintf(stdout, "max %d\n", stack->max);
}

static int usage(void)
{
	fputs("usage: tester [args] socket\n", stderr);
	fputs("    -v     	Enable verbose (default:disabled)\n", stderr);
	fputs("    -f file    	FIFO to use as a ready indicator\n", stderr);
	return 2;
}

int main(int argc, char *argv[])
{
	char *main = "main";
	int i;
	while ((i = getopt(argc, argv, "hqvm:")) > 0) {
		switch (i) {
		case 'm':
			main = optarg;
			break;
		case 'q':
			g_log_level = LOG_WARNING;
			break;
		case 'v':
			g_log_level = LOG_VERBOSE;
			break;
		case 'h':
		case '?':
			return usage();
		}
	}

	argc -= optind;
	argv += optind;

	g_nodes = kh_init(node);

	for (int i = 0; i < argc; i++) {
		char *buf;
		size_t sz;
		if (sys_slurp(argv[i], &buf, &sz)) {
			return -1;
		}
		parse_file(argv[i], buf, sz);
		// leave the buffer allocated
	}

	khint_t idx = kh_get(node, g_nodes, main);
	if (idx == kh_end(g_nodes)) {
		FATAL("no main function,main:%s", main);
	}
	struct node *n = kh_val(g_nodes, idx);
	print_stack(n);

	return 0;
}
