#include "messages.h"
#include "page.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

void gc_msg_data(void *p)
{
	struct msg_data *m = p;
	deref_paged_data(m->data.p);
}

void gc_msg_file(void *p)
{
	struct msg_file *m = p;
#ifdef _WIN32
	CloseHandle(m->file);
#else
	close(m->file);
#endif
}
void gc_cmd_name(void *p)
{
	struct cmd_name *m = p;
	deref_paged_data(m->name.p);
}

void gc_update_sub(void *p)
{
	struct cmd_update_sub *c = p;
	deref_paged_data(c->s.m.base);
}

void gc_name(void*p)
{
	struct msg_name *m = p;
	deref_paged_data(m->name.p);
}
