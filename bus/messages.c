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
	deref_paged_data(m->data.p, 1);
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

struct cmd_name make_cmd_name(struct remote *r, slice_t name, uint32_t reply)
{
	struct cmd_name ret;
	ret.remote = r;
	ret.name = name;
	ret.reply_serial = reply;
	ref_paged_data(ret.name.p, 1);
	return ret;
}

void gc_cmd_name(void *p)
{
	struct cmd_name *m = p;
	deref_paged_data(m->name.p, 1);
}
