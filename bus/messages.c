#include "messages.h"
#include "page.h"

//////////////////////////
// MSG_DATA

static_assert(sizeof(struct msg_data) <= MSGQ_DATA_SIZE, "");

void send_msg_data(void *p)
{
	struct msg_data *m = p;
	ref_paged_data(m->data.p);
}

void destroy_msg_data(void *p)
{
	struct msg_data *m = p;
	deref_paged_data(m->data.p);
}

msg_type_t msg_data_vt = {
	.code = MSG_DATA,
	.destroy = &destroy_msg_data,
	.send = &send_msg_data,
};

///////////////////////////////////
// MSG_FILE

static_assert(sizeof(struct msg_file) <= MSGQ_DATA_SIZE, "");

void destroy_msg_file(void *p)
{
	struct msg_file *m = p;
#ifdef _WIN32
	CloseHandle(m->fd);
#else
	close(m->fd);
#endif
}

msg_type_t msg_file_vt = {
	.code = MSG_FILE,
	.destroy = &destroy_msg_file,
};

//////////////////////////////////////
// MSG_DISCONNECTED

static_assert(sizeof(struct msg_disconnected) <= MSGQ_DATA_SIZE, "");

msg_type_t msg_disconnected_vt = {
	.code = MSG_DISCONNECTED,
};

///////////////////////////////////////////
// CMD_REGISTER

static_assert(sizeof(struct cmd_register) <= MSGQ_DATA_SIZE, "");

msg_type_t cmd_register_vt = {
	.code = CMD_REGISTER,
};

/////////////////////////////////////
// REP_REGISTER

msg_type_t rep_register_vt = {
	.code = REP_REGISTER,
};

//////////////////////////////////
// CMD_UPDATE_NAME

static_assert(sizeof(struct cmd_update_name) <= MSGQ_DATA_SIZE, "");

static void destroy_update_name(void *p)
{
	struct cmd_update_name *m = p;
	deref_paged_data(m->name.p);
}

static void send_update_name(void *p)
{
	struct cmd_update_name *m = p;
	ref_paged_data(m->name.p);
}

msg_type_t cmd_update_name_vt = {
	.code = CMD_UPDATE_NAME,
	.destroy = &destroy_update_name,
	.send = &send_update_name,
};

////////////////////////////////////////
// CMD_UPDATE_NAME_SUB

static_assert(sizeof(struct cmd_update_name_sub) <= MSGQ_DATA_SIZE, "");

msg_type_t cmd_update_name_sub_vt = {
	.code = CMD_UPDATE_NAME_SUB,
};

////////////////////////////////////
// CMD_UPDATE_UCAST_SUB

static_assert(sizeof(struct cmd_update_ucast_sub) <= MSGQ_DATA_SIZE, "");

msg_type_t cmd_update_ucast_sub_vt = {
	.code = CMD_UPDATE_UCAST_SUB,
};

////////////////////////////////////
// CMD_UPDATE_BCAST_SUB

static_assert(sizeof(struct cmd_update_bcast_sub) <= MSGQ_DATA_SIZE, "");

msg_type_t cmd_update_bcast_sub_vt = {
	.code = CMD_UPDATE_BCAST_SUB,
};

/////////////////////////////////
// MSG_NAME

static_assert(sizeof(struct msg_name) <= MSGQ_DATA_SIZE, "");

static void destroy_msg_name(void *p)
{
	struct msg_name *m = p;
	deref_paged_data(m->name.p);
}

static void send_msg_name(void *p)
{
	struct msg_name *m = p;
	ref_paged_data(m->name.p);
}

msg_type_t msg_name_vt = {
	.code = MSG_NAME,
	.destroy = &destroy_msg_name,
	.send = &send_msg_name,
};

///////////////////////////////////////
// errcode replies

static_assert(sizeof(struct rep_errcode) <= MSGQ_DATA_SIZE, "");

msg_type_t rep_update_name_vt = {
	.code = REP_UPDATE_NAME,
};
msg_type_t rep_update_name_sub_vt = {
	.code = REP_UPDATE_NAME_SUB,
};
msg_type_t rep_update_ucast_sub_vt = {
	.code = REP_UPDATE_UCAST_SUB,
};
msg_type_t rep_update_bcast_sub_vt = {
	.code = REP_UPDATE_BCAST_SUB,
};
