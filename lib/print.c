#include "print.h"
#include <string.h>
#include <limits.h>

size_t print_int32(char *buf, int32_t num)
{
	char *e = buf + PRINT_INT32_LEN;
	char *p = e;
	int sign = 0;
	if (num < 0) {
		sign = 1;
		num = -num;
	}
	do {
		*--p = '0' + (num % 10);
		num /= 10;
	} while (num);
	if (sign) {
		*--p = '-';
	}
	size_t n = e - p;
	memmove(buf, p, n);
	return n;
}

size_t print_int64(char *buf, int64_t num)
{
	char *e = buf + PRINT_INT64_LEN;
	char *p = e;
	int sign = 0;
	if (num < 0) {
		sign = 1;
		num = -num;
	}
	do {
		*--p = '0' + (num % 10);
		num /= 10;
	} while (num);
	if (sign) {
		*--p = '-';
	}
	size_t n = e - p;
	memmove(buf, p, n);
	return n;
}

size_t print_uint32(char *buf, uint32_t num)
{
	char *e = buf + PRINT_UINT32_LEN;
	char *p = e;
	do {
		*--p = '0' + (num % 10);
		num /= 10;
	} while (num);
	size_t n = e - p;
	memmove(buf, p, n);
	return n;
}

size_t print_uint64(char *buf, uint64_t num)
{
	char *e = buf + PRINT_UINT64_LEN;
	char *p = e;
	do {
		*--p = '0' + (num % 10);
		num /= 10;
	} while (num);
	size_t n = e - p;
	memmove(buf, p, n);
	return n;
}

int parse_pos_int(const char *p, int *pval)
{
	if (*p < '0' || *p > '9') {
		return 0;
	} else if (*p == '0') {
		*pval = 0;
		return 1;
	}
	int n = 0;
	int ret = p[n++] - '0';
	for (;;) {
		if (p[n] < '0' || p[n] > '9') {
			*pval = ret;
			return n;
		} else if (ret >= (INT_MAX / 10)) {
			return -1;
		}
		ret = (ret * 10) + (p[n++] - '0');
	}
}

static void ReplaceUtf8(uint8_t **dp, const uint16_t **sp)
{
	/* Insert the replacement character */
	(*dp)[0] = 0xEF;
	(*dp)[1] = 0xBF;
	(*dp)[2] = 0xBD;
	*dp += 3;
	*sp += 1;
}

char *utf16_to_utf8(char *dst, const uint16_t *src, size_t len)
{
	uint8_t *dp = (uint8_t *)dst;
	const uint16_t *sp = src;
	const uint16_t *send = src + len;

	while (sp < send) {
		if (sp[0] < 0x80) {
			/* 1 chars utf8, 1 wchar utf16 (US-ASCII)
			 * UTF32:  00000000 00000000 00000000 0xxxxxxx
			 * Source: 00000000 0xxxxxxx
			 * Dest:   0xxxxxxx
			 */
			dp[0] = (uint8_t)sp[0];
			dp += 1;
			sp += 1;
		} else if (sp[0] < 0x800) {
			/* 2 chars utf8, 1 wchar utf16
			 * UTF32:  00000000 00000000 00000yyy xxxxxxxx
			 * Source: 00000yyy xxxxxxxx
			 * Dest:   110yyyxx 10xxxxxx
			 */
			dp[0] = (uint8_t)(0xC0 | ((sp[0] >> 6) & 0x1F));
			dp[1] = (uint8_t)(0x80 | (sp[0] & 0x3F));
			dp += 2;
			sp += 1;
		} else if (sp[0] < 0xD800) {
			/* 3 chars utf8, 1 wchar utf16
			 * UTF32:  00000000 00000000 yyyyyyyy xxxxxxxx
			 * Source: yyyyyyyy xxxxxxxx
			 * Dest:   1110yyyy 10yyyyxx 10xxxxxx
			 */
			dp[0] = (uint8_t)(0xE0 | ((sp[0] >> 12) & 0x0F));
			dp[1] = (uint8_t)(0x80 | ((sp[0] >> 6) & 0x3F));
			dp[2] = (uint8_t)(0x80 | (sp[0] & 0x3F));
			dp += 3;
			sp += 1;
		} else if (sp[0] < 0xDC00) {
			/* 4 chars utf8, 2 wchars utf16
			 * 0xD8 1101 1000
			 * 0xDB 1101 1011
			 * 0xDC 1101 1100
			 * 0xDF 1101 1111
			 * UTF32:  00000000 000zzzzz yyyyyyyy xxxxxxxx
			 * Source: 110110zz zzyyyyyy 110111yy xxxxxxxx
			 * Dest:   11110zzz 10zzyyyy 10yyyyxx 10xxxxxx
			 * UTF16 data is shifted by 0x10000
			 */
			if (sp + 1 > send) {
				ReplaceUtf8(&dp, &sp);
			} else if (!(0xDC00 <= sp[1] &&
				     sp[1] <= 0xDFFF)) { /* Check for a valid
							    surrogate */
				ReplaceUtf8(&dp, &sp);
			} else {
				uint32_t u32 =
					((((uint32_t)sp[0]) << 10) & 0x0FFC00) |
					(((uint32_t)sp[1]) & 0x3FF);
				u32 += 0x10000;
				dp[0] = (uint8_t)(0xF0 | ((u32 >> 18) & 0x03));
				dp[1] = (uint8_t)(0x80 | ((u32 >> 12) & 0x3F));
				dp[2] = (uint8_t)(0x80 | ((u32 >> 6) & 0x3F));
				dp[3] = (uint8_t)(0x80 | (u32 & 0x3F));
				dp += 4;
				sp += 2;
			}
		} else {
			/* 3 chars utf8, 1 wchar utf16
			 * UTF32:  00000000 00000000 yyyyyyyy xxxxxxxx
			 * Source: yyyyyyyy xxxxxxxx
			 * Dest:   1110yyyy 10yyyyxx 10xxxxxx
			 */
			dp[0] = (uint8_t)(0xE0 | ((sp[0] >> 12) & 0x0F));
			dp[1] = (uint8_t)(0x80 | ((sp[0] >> 6) & 0x3F));
			dp[2] = (uint8_t)(0x80 | (sp[0] & 0x3F));
			dp += 3;
			sp += 1;
		}
	}
	return (char *)dp;
}

static void ReplaceUtf16(uint16_t **dp, const uint8_t **sp, int srcskip)
{
	/* Insert the replacement character */
	**dp = 0xFFFD;
	*dp += 1;
	*sp += srcskip;
}

uint16_t *utf8_to_utf16(uint16_t *dst, const char *src, size_t len)
{
	uint16_t *dp = dst;
	const uint8_t *sp = (uint8_t *)src;
	const uint8_t *send = sp + len;

	while (sp < send) {
		if (sp[0] < 0x80) {
			/* 1 char utf8, 1 wchar utf16 (US-ASCII)
			 * UTF32:  00000000 00000000 00000000 0xxxxxxx
			 * Source: 0xxxxxxx
			 * Dest:   00000000 0xxxxxxx
			 */
			dp[0] = sp[0];
			dp += 1;
			sp += 1;
		} else if (sp[0] < 0xC0) {
			/* Multi-byte data without start */
			ReplaceUtf16(&dp, &sp, 1);
		} else if (sp[0] < 0xE0) {
			/* 2 chars utf8, 1 wchar utf16
			 * UTF32:  00000000 00000000 00000yyy xxxxxxxx
			 * Source: 110yyyxx 10xxxxxx
			 * Dest:   00000yyy xxxxxxxx
			 * Overlong: Require 1 in some y or top bit of x
			 */
			if (sp + 2 > send) {
				ReplaceUtf16(&dp, &sp, 1);
			} else if ((sp[1] & 0xC0) != 0x80) { /* Check
								continuation
								byte */
				ReplaceUtf16(&dp, &sp, 1);
			} else if ((sp[1] & 0x1E) == 0) { /* Check for overlong
							     encoding */
				ReplaceUtf16(&dp, &sp, 2);
			} else {
				dp[0] = ((((uint16_t)sp[0]) & 0x1F) << 6) |
					(((uint16_t)sp[1]) & 0x3F);
				dp += 1;
				sp += 2;
			}
		} else if (sp[0] < 0xF0) {
			/* 3 chars utf8, 1 wchar utf16
			 * UTF32:  00000000 00000000 yyyyyyyy xxxxxxxx
			 * Source: 1110yyyy 10yyyyxx 10xxxxxx
			 * Dest:   yyyyyyyy xxxxxxxx
			 * Overlong: Require 1 in one of the top 5 bits of y
			 */
			if (sp + 3 > send) {
				ReplaceUtf16(&dp, &sp, 1);
			} else if ((sp[1] & 0xC0) != 0x80) { /* Check
								continuation
								byte */
				ReplaceUtf16(&dp, &sp, 1);
			} else if ((sp[2] & 0xC0) != 0x80) { /* Check
								continuation
								byte */
				ReplaceUtf16(&dp, &sp, 1);
			} else if ((sp[0] & 0x0F) == 0 &&
				   (sp[1] & 0x20) == 0) { /* Check for overlong
							     encoding */
				ReplaceUtf16(&dp, &sp, 3);
			} else {
				dp[0] = ((((uint16_t)sp[0]) & 0x0F) << 12) |
					((((uint16_t)sp[1]) & 0x3F) << 6) |
					(((uint16_t)sp[2]) & 0x3F);
				dp += 1;
				sp += 3;
			}
		} else if (sp[0] < 0xF8) {
			/* 4 chars utf8, 2 wchars utf16
			 * UTF32:  00000000 000zzzzz yyyyyyyy xxxxxxxx
			 * Source: 110110zz zzyyyyyy 110111yy xxxxxxxx
			 * Dest:   11110zzz 10zzyyyy 10yyyyxx 10xxxxxx
			 * Overlong: Check UTF32 value
			 * UTF16 data is shifted by 0x10000
			 */
			if (sp + 4 > send) {
				ReplaceUtf16(&dp, &sp, 1);
			} else if ((sp[1] & 0xC0) != 0x80) { /* Check
								continuation
								byte */
				ReplaceUtf16(&dp, &sp, 1);
			} else if ((sp[2] & 0xC0) != 0x80) { /* Check
								continuation
								byte */
				ReplaceUtf16(&dp, &sp, 1);
			} else if ((sp[3] & 0xC0) != 0x80) { /* Check
								continuation
								byte */
				ReplaceUtf16(&dp, &sp, 1);
			} else {
				uint32_t u32 =
					((((uint16_t)sp[0]) & 0x07) << 18) |
					((((uint16_t)sp[1]) & 0x3F) << 12) |
					((((uint16_t)sp[2]) & 0x3F) << 6) |
					(((uint16_t)sp[3]) & 0x3F);

				/* Check for overlong or too long encoding */
				if (u32 < 0x10000 || u32 > 0x10FFFF) {
					ReplaceUtf16(&dp, &sp, 4);
				} else {
					u32 -= 0x10000;
					dp[0] = (uint16_t)(0xD800 |
							   ((u32 >> 10) &
							    0x3FF));
					dp[1] = (uint16_t)(0xDC00 |
							   (u32 & 0x3FF));
					dp += 2;
					sp += 4;
				}
			}
		} else {
			ReplaceUtf16(&dp, &sp, 1);
		}
	}
	return dp;
}
