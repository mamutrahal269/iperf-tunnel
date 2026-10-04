#include "client.h"
#include "iperf.h"
#include "iperf_api.h"
#include "server.h"
#include "tunnel.h"

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s c <host> | s\n", argv[0]);
    return 1;
  }

  struct iperf_test *test = iperf_new_test();
  iperf_defaults(test);
  iperf_set_test_logfile(test, "/dev/null");
  if (argv[1][0] == 'c') {
    if (argc < 3) {
      fprintf(stderr, "usage: %s c <host>\n", argv[0]);
      return 1;
    }
    iperf_set_test_role(test, 'c');
    iperf_set_test_bidirectional(test, 1);
    iperf_set_test_server_hostname(test, argv[2]);
    iperf_set_test_duration(test, 0);
    tunnel_client_init(test);
    if (iperf_run_client(test) < 0) {
      fprintf(stderr, "iperf: %s\n", iperf_strerror(i_errno));
    }
    tunnel_client_cleanup();
  } else if (argv[1][0] == 's') {
    iperf_set_test_role(test, 's');
    tunnel_server_init(test);
    while (1) {
      iperf_run_server(test);
      iperf_reset_test(test);
      tunnel_server_cleanup();
    }
  }
  return 0;
}
