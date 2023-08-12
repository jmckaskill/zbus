#pragma once
#include <stddef.h>

extern int check_string(const char *s, size_t len);
extern int check_path(const char *s, size_t len);
extern int check_member(const char *s, size_t len);
extern int check_interface(const char *s, size_t len);
extern int check_address(const char *s, size_t len);
extern int check_unique_address(const char *s, size_t len);
static int check_error_name(const char *s, size_t len);
static int check_known_address(const char *s, size_t len);

/////////////////////////
// inline implementations

static inline int check_error_name(const char *s, size_t len)
{
	return check_interface(s, len);
}

static inline int check_known_address(const char *s, size_t len)
{
	return check_interface(s, len);
}
