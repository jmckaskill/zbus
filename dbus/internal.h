#pragma once
#include "types.h"

#define FTAG_PATH UINT32_C(0x006F0101) // BYTE: 01 SIG: "o"
#define FTAG_INTERFACE UINT32_C(0x00730102) // BYTE: 02 SIG: "s"
#define FTAG_MEMBER UINT32_C(0x00730103) // BYTE: 03 SIG: "s"
#define FTAG_ERROR_NAME UINT32_C(0x00730104) // BYTE: 04 SIG: "s"
#define FTAG_REPLY_SERIAL UINT32_C(0x00750105) // BYTE: 05 SIG: "u"
#define FTAG_DESTINATION UINT32_C(0x00730106) // BYTE: 06 SIG: "s"
#define FTAG_SENDER UINT32_C(0x00730107) // BYTE: 07 SIG: "s"
#define FTAG_SIGNATURE UINT32_C(0x00670108) // BYTE: 08 SIG: "g"
#define FTAG_UNIX_FDS UINT32_C(0x00750109) // BYTE: 09 SIG: "u"

#define DBUS_VERSION 1

struct raw_header {
	uint8_t endian;
	uint8_t type;
	uint8_t flags;
	uint8_t version;
	uint8_t body_len[4];
	uint8_t serial[4];
	uint8_t field_len[4];
};

ZB_INLINE uint8_t native_endian(void)
{
	union test {
		uint16_t u;
		uint8_t b[2];
	} test;
	test.u = 0x426C; // "Bl"
	return test.b[0];
}
