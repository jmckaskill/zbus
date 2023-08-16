#pragma once
#include "types.h"
#include <stddef.h>

ZB_EXTERN int zb_check_path(const char *s, size_t len);
ZB_EXTERN int zb_check_member(const char *s, size_t len);
ZB_EXTERN int zb_check_interface(const char *s, size_t len);
ZB_EXTERN int zb_check_address(const char *s, size_t len);
ZB_EXTERN int zb_check_unique_address(const char *s, size_t len);
ZB_INLINE int zb_check_error_name(const char *s, size_t len);
ZB_INLINE int zb_check_known_address(const char *s, size_t len);

/////////////////////////
// inline implementations

ZB_INLINE int zb_check_error_name(const char *s, size_t len)
{
	return zb_check_interface(s, len);
}

ZB_INLINE int zb_check_known_address(const char *s, size_t len)
{
	return zb_check_interface(s, len);
}
