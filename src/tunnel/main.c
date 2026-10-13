#include "client.h"
#include "iperf.h"
#include "iperf_api.h"
#include "iperf_auth.h"
#include "server.h"
#include "tunnel.h"

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  static struct option const opts[] = {
      {"help", no_argument, 0, 'h'},
      {"client", required_argument, 0, 'c'},
      {"server", no_argument, 0, 's'},
      {"port", required_argument, 0, 'p'},

      {"length", required_argument, 0, 'l'},
      {"username", required_argument, 0, OPT_CLIENT_USERNAME},
      {"rsa-public-key-path", required_argument, 0, OPT_CLIENT_RSA_PUBLIC_KEY},
      {"rsa-private-key-path", required_argument, 0,
       OPT_SERVER_RSA_PRIVATE_KEY},
      {"authorized-users-path", required_argument, 0,
       OPT_SERVER_AUTHORIZED_USERS},
      {0, 0, 0, 0}};

  struct iperf_test *test = iperf_new_test();
  iperf_defaults(test);

  int opt;
  opterr = 1;
  while ((opt = getopt_long(argc, argv, "hc:sp:l:", opts, NULL)) != -1) {
    switch (opt) {
    case 'h':
      // clang-format off
      printf("Usage: iperf-tunnel [-s|-c host] [options]\n");
      printf("Options:\n");
      printf("  -h, --help                print this page\n");
      printf("  -c, --client              run in client mode, connecting to <host>\n");
      printf("  -s, --server              run in server mode\n");
      printf("  -p, --port                server port to listen on/connect to\n");
      printf("  -l, --length              size of tunnel frame\n");
      printf("  --username                username for authentication\n");
      printf("  --rsa-public-key-path     path to the RSA public key used to encrypt\n");
      printf("  --rsa-private-key-path    path to the RSA private key used to decrypt\n");
      printf("  --authorized-users-path   path to the configuration file containing user\n");
      // clang-format on
      return 0;
    case 'c':
      iperf_set_test_role(test, 'c');
      iperf_set_test_server_hostname(test, optarg);
      break;
    case 's':
      iperf_set_test_role(test, 's');
      break;
    case 'p':
      iperf_set_test_server_port(test, atoi(optarg));
      break;
    case 'l':
      iperf_set_test_blksize(test, atoi(optarg));
      break;
    case OPT_CLIENT_USERNAME:
      iperf_set_test_client_username(test, optarg);
      break;
    case OPT_CLIENT_RSA_PUBLIC_KEY:
      iperf_set_test_client_rsa_pubkey_from_file(test, optarg);
      break;
    case OPT_SERVER_RSA_PRIVATE_KEY:
      iperf_set_test_server_rsa_privkey_from_file(test, optarg);
      break;
    case OPT_SERVER_AUTHORIZED_USERS:
      iperf_set_test_server_authorized_users(test, optarg);
      break;
    default:
      fprintf(stderr, "unknown option: '%c'\n", opt);
    }
  }

  signal(SIGPIPE, SIG_IGN);
  iperf_set_test_logfile(test, "/dev/null");

  switch (iperf_get_test_role(test)) {
  case 'c': {
    iperf_set_test_bidirectional(test, 1);
    iperf_set_test_duration(test, 0);

    char *pw = NULL;
    if ((pw = getenv("IPERF3_PASSWORD")) != NULL) {
      pw = strdup(pw);
    }
    test->settings->client_password = pw;

    tunnel_client_init(test);
    if (iperf_run_client(test) < 0) {
      fprintf(stderr, "iperf: %s\n", iperf_strerror(i_errno));
      exit(EXIT_FAILURE);
    }
    break;
  }
  case 's':
    tunnel_server_init(test);
    for (;;) {
      if (iperf_run_server(test) < 0) {
        fprintf(stderr, "iperf: %s\n", iperf_strerror(i_errno));
      }
      tunnel_server_cleanup();
      iperf_reset_test(test);
    }
  default:
    fprintf(stderr, "role not specified\n");
    exit(EXIT_FAILURE);
  }
}
