#pragma once

#include "iperf.h"
#include "iperf_api.h"

extern const char *tunnel_socks5_addr;
extern int tunnel_socks5_port;

void tunnel_client_init(struct iperf_test *test);
void tunnel_client_cleanup(void);
