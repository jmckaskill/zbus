#pragma once
#include "rx.h"
#include "dbus/decode.h"

#define BUS_DESTINATION S8("\024org.freedesktop.DBus")
#define BUS_PATH S8("\025/org/freedesktop/DBus")

#define BUS_INTERFACE S8("\024org.freedesktop.DBus")
#define METHOD_GET_ID S8("\005GetId") // 5
#define METHOD_HELLO S8("\005Hello") // 5
#define METHOD_ADD_MATCH S8("\010AddMatch") // 8
#define METHOD_LIST_NAMES S8("\011ListNames") // 9
#define METHOD_REQUEST_NAME S8("\013RequestName") // 11
#define METHOD_RELEASE_NAME S8("\013ReleaseName") // 11
#define METHOD_REMOVE_MATCH S8("\013RemoveMatch") // 11
#define METHOD_NAME_HAS_OWNER S8("\014NameHasOwner") // 12
#define METHOD_GET_NAME_OWNER S8("\014GetNameOwner") // 12
#define METHOD_LIST_QUEUED_OWNERS S8("\020ListQueuedOwners") // 16
#define METHOD_START_SERVICE S8("\022StartServiceByName") // 18
#define METHOD_LIST_ACTIVATABLE_NAMES S8("\024ListActivatableNames") // 20
#define METHOD_GET_UNIX_USER S8("\025GetConnectionUnixUser") // 21
#define METHOD_GET_ADT S8("\026GetAdtAuditSessionData") // 22
#define METHOD_GET_CREDENTIALS S8("\028GetConnectionCredentials") // 24
#define METHOD_GET_UNIX_PROCESS_ID S8("\032GetConnectionUnixProcessID") // 26
#define METHOD_UPDATE_ENVIRONMENT S8("\033UpdateActivationEnvironment") // 27
#define METHOD_GET_SELINUX S8("\043GetConnectionSELinuxSEcurityContext") // 35

#define SIGNAL_NAME_OWNER_CHANGED S8("\020NameOwnerChanged")
#define SIGNAL_NAME_ACQUIRED S8("\014NameAcquired")
#define SIGNAL_NAME_LOST S8("\010NameLost")

#define MONITORING_INTERFACE S8("\037org.freedesktop.DBus.Monitoring")
#define METHOD_BECOME_MONITOR S("\015BecomeMonitor")

#define PEER_INTERFACE S8("\031org.freedesktop.DBus.Peer")
#define METHOD_PING S8("\004Ping")

int bus_method(struct rx *r, struct message *m, struct iterator *ii);
int peer_method(struct rx *r, struct message *m);
int unicast(struct rx *r, struct tx_msg *m);
int broadcast(struct rx *r, struct tx_msg *m);
int build_reply(struct rx *r, struct tx_msg *m);

void rm_all_names_locked(struct rx *r);
void rm_all_matches_locked(struct rx *r);
