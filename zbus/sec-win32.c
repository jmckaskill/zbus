#include "sec.h"

#ifdef HAVE_SID
#include "lib/windows.h"
#include "lib/log.h"
#include <sddl.h>

void free_security(struct security *p)
{
	if (p) {
		LocalFree(p->sid);
		free(p);
	}
}

bool g_enable_security = false;

int load_security(struct txconn *c, struct security **pp)
{
	if (!g_enable_security) {
		*pp = NULL;
		return 0;
	}

	HANDLE tok = INVALID_HANDLE_VALUE;
	ULONG pid;
	if (!GetNamedPipeClientProcessId(c->h, &pid)) {
		ERROR("failed to get pipe client pid,errno:%m");
		goto error;
	}
	if (!ImpersonateNamedPipeClient(c->h)) {
		ERROR("failed to impersonate pipe client,errno:%m");
		goto error;
	}

	if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY_SOURCE, TRUE,
			     &tok)) {
		ERROR("failed to open impersonated token,errno:%m");
		goto error;
	}

	TOKEN_OWNER owner;
	DWORD sz;
	if (!GetTokenInformation(tok, TokenOwner, &owner, sizeof(owner), &sz) ||
	    sz != sizeof(owner)) {
		ERROR("failed to get sid,errno:%m");
		goto error;
	}

	char *sid;
	if (!ConvertSidToStringSidA(owner.Owner, &sid)) {
		ERROR("failed to convert sid to string,errno:%m");
		goto error;
	}

	struct security *p = fmalloc(sizeof(*p));
	p->pid = (uint32_t)pid;
	p->sid = sid;
	*pp = p;

	CloseHandle(tok);
	return 0;

error:
	CloseHandle(tok);
	return -1;
}

int getentropy(void *buf, size_t sz)
{
	HCRYPTPROV h;
	if (!CryptAcquireContextW(&h, NULL, MS_DEF_PROV_W, PROV_RSA_FULL,
				  CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
		ERROR("failed to acquire cyrpt context,errno:%m");
		return -1;
	}
	int err = 0;
	if (!CryptGenRandom(h, (DWORD)sz, buf)) {
		ERROR("failed to generate random,errno:%m");
		err = -1;
	}
	CryptReleaseContext(h, 0);
	return err;
}

#endif
