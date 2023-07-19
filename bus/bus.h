#pragma once

struct rcu_data {
	char *test_string;
};

int setup_signals();
int bind_bus(const char *sockpn);
int run_bus(int lfd);
