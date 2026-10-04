#pragma once

#include "iperf.h"
#include "iperf_api.h"

void tunnel_server_init(struct iperf_test *test);
void tunnel_server_cleanup();
