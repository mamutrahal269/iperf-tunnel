#pragma once

#include "iperf.h"
#include "iperf_api.h"

void tunnel_client_init(struct iperf_test *test);
void tunnel_client_cleanup(void);
