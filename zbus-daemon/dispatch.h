#pragma once
#include "config.h"
#include "rx.h"
#include "zbus/zbus.h"

#define BUS_DESTINATION ZB_S8("\024org.freedesktop.DBus")
#define BUS_PATH ZB_S8("\025/org/freedesktop/DBus")

#define BUS_INTERFACE ZB_S8("\024org.freedesktop.DBus")
#define METHOD_GET_ID ZB_S8("\005GetId") // 5
#define METHOD_HELLO ZB_S8("\005Hello") // 5
#define METHOD_ADD_MATCH ZB_S8("\010AddMatch") // 8
#define METHOD_LIST_NAMES ZB_S8("\011ListNames") // 9
#define METHOD_REQUEST_NAME ZB_S8("\013RequestName") // 11
#define METHOD_RELEASE_NAME ZB_S8("\013ReleaseName") // 11
#define METHOD_REMOVE_MATCH ZB_S8("\013RemoveMatch") // 11
#define METHOD_NAME_HAS_OWNER ZB_S8("\014NameHasOwner") // 12
#define METHOD_GET_NAME_OWNER ZB_S8("\014GetNameOwner") // 12
#define METHOD_LIST_QUEUED_OWNERS ZB_S8("\020ListQueuedOwners") // 16
#define METHOD_START_SERVICE ZB_S8("\022StartServiceByName") // 18
#define METHOD_LIST_ACTIVATABLE_NAMES ZB_S8("\024ListActivatableNames") // 20
#define METHOD_GET_UNIX_USER ZB_S8("\025GetConnectionUnixUser") // 21
#define METHOD_GET_ADT ZB_S8("\026GetAdtAuditSessionData") // 22
#define METHOD_GET_CREDENTIALS ZB_S8("\028GetConnectionCredentials") // 24
#define METHOD_GET_UNIX_PROCESS_ID ZB_S8("\032GetConnectionUnixProcessID") // 26
#define METHOD_UPDATE_ENVIRONMENT ZB_S8("\033UpdateActivationEnvironment") // 27
#define METHOD_GET_SELINUX \
	ZB_S8("\043GetConnectionSELinuxSEcurityContext") // 35

#define SIGNAL_NAME_OWNER_CHANGED ZB_S8("\020NameOwnerChanged")
#define SIGNAL_NAME_ACQUIRED ZB_S8("\014NameAcquired")
#define SIGNAL_NAME_LOST ZB_S8("\010NameLost")

#define MONITORING_INTERFACE ZB_S8("\037org.freedesktop.DBus.Monitoring")
#define METHOD_BECOME_MONITOR S("\015BecomeMonitor")

#define PEER_INTERFACE ZB_S8("\031org.freedesktop.DBus.Peer")
#define METHOD_PING ZB_S8("\004Ping")

int bus_method(struct rx *r, struct zb_message *m, struct zb_iterator *ii);
int peer_method(struct rx *r, struct zb_message *m);
int unicast(struct rx *r, struct txmsg *m);
int broadcast(struct rx *r, struct txmsg *m);
int build_reply(struct rx *r, struct txmsg *m);

void rm_all_names_locked(struct rx *r);
void rm_all_matches_locked(struct rx *r);
