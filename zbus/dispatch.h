#pragma once
#include "rx.h"
#include "lib/decode.h"

#define BUS_DESTINATION S("org.freedesktop.DBus")
#define BUS_PATH S("/org/freedesktop/DBus")

#define BUS_INTERFACE S("org.freedesktop.DBus")
#define METHOD_GET_ID S("GetId") // 5
#define METHOD_HELLO S("Hello") // 5
#define METHOD_ADD_MATCH S("AddMatch") // 8
#define METHOD_LIST_NAMES S("ListNames") // 9
#define METHOD_REQUEST_NAME S("RequestName") // 11
#define METHOD_RELEASE_NAME S("ReleaseName") // 11
#define METHOD_REMOVE_MATCH S("RemoveMatch") // 11
#define METHOD_NAME_HAS_OWNER S("NameHasOwner") // 12
#define METHOD_GET_NAME_OWNER S("GetNameOwner") // 12
#define METHOD_LIST_QUEUED_OWNERS S("ListQueuedOwners") // 16
#define METHOD_START_SERVICE S("StartServiceByName") // 18
#define METHOD_LIST_ACTIVATABLE_NAMES S("ListActivatableNames") // 20
#define METHOD_GET_UNIX_USER S("GetConnectionUnixUser") // 21
#define METHOD_GET_ADT S("GetAdtAuditSessionData") // 22
#define METHOD_GET_CREDENTIALS S("GetConnectionCredentials") // 24
#define METHOD_GET_UNIX_PROCESS_ID S("GetConnectionUnixProcessID") // 26
#define METHOD_UPDATE_ENVIRONMENT S("UpdateActivationEnvironment") // 27
#define METHOD_GET_SELINUX S("GetConnectionSELinuxSEcurityContext") // 35

#define SIGNAL_NAME_OWNER_CHANGED S("NameOwnerChanged")
#define SIGNAL_NAME_ACQUIRED S("NameAcquired")
#define SIGNAL_NAME_LOST S("NameLost")

#define MONITORING_INTERFACE S("org.freedesktop.DBus.Monitoring")
#define METHOD_BECOME_MONITOR S("BecomeMonitor")

#define PEER_INTERFACE S("org.freedesktop.DBus.Peer")
#define METHOD_PING S("Ping")

int check_fields(struct message *m);
int dispatch(struct rx *r, const struct message *m, struct rope *body);
void rm_all_names_locked(struct rx *r);
void rm_all_matches_locked(struct rx *r);
