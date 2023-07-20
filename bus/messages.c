#include "messages.h"
#include "page.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

void gc_send_data(void *p)
{
	struct msg_send_data *m = p;
	deref_paged_data(m->data.p, 1);
}

void gc_send_file(void *p)
{
	struct msg_send_file *m = p;
#ifdef _WIN32
	CloseHandle(m->file);
#else
	close(m->file);
#endif
}

void gc_request_name(void *p)
{
	struct cmd_request_name *m = p;
	deref_paged_data(m->name.p, 1);
}

void gc_release_name(void *p)
{
	struct cmd_release_name *m = p;
	deref_paged_data(m->name.p, 1);
}
