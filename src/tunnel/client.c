#include "iperf_config.h"

#include "client.h"
#include "iperf.h"
#include "iperf_api.h"
#include "net.h"
#include "queue.h"
#include "tunnel.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/poll.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <unistd.h>
#include <uthash.h>

#define LISTEN_ADDR "127.0.0.1"
#define LISTEN_PORT 8888

typedef struct {
  uint64_t id;
  struct queue *q;
  UT_hash_handle hh;
} tunnel_wentry;
typedef struct {
  tunnel_wentry *ent;
  int sockfd;
  int blksize;
} tunnel_wargs;

static tunnel_wentry *tbl;
static pthread_mutex_t tbl_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_t cli_th;
static int efd_cli_exit = -1;
static __attribute__((constructor)) void efd_init() {
  if ((efd_cli_exit = eventfd(0, EFD_SEMAPHORE)) < 0) {
    PERR("eventfd");
    exit(EXIT_FAILURE);
  }
}

static void socks5_reply(int fd, uint8_t rep) {
  /* VER REP RSV ATYP=IPv4 BND.ADDR=0.0.0.0 BND.PORT=0 */
  uint8_t r[10] = {5, rep, 0, 1, 0, 0, 0, 0, 0, 0};
  (void)write_blk(fd, (char *)r, sizeof(r));
}

static int socks5_handshake(int fd, char *host, size_t host_sz,
                            uint16_t *port) {
  uint8_t b[4];

  /* greeting: VER NMETHODS METHODS... */
  if (read_blk(fd, b, 2) || b[0] != 5) {
    return -1;
  }
  uint8_t methods[255];
  if (b[1] == 0 || read_blk(fd, methods, b[1])) {
    return -1;
  }
  int no_auth = 0;
  for (int i = 0; i < b[1]; i++) {
    if (methods[i] == 0x00) {
      no_auth = 1;
    }
  }
  uint8_t sel[2] = {5, no_auth ? 0x00 : 0xFF};
  if (write_blk(fd, (char *)sel, 2) || !no_auth) {
    return -1;
  }

  /* request: VER CMD RSV ATYP */
  if (read_blk(fd, b, 4) || b[0] != 5) {
    return -1;
  }
  if (b[1] != 0x01) { /* only CONNECT */
    socks5_reply(fd, 0x07);
    return -1;
  }

  switch (b[3]) {
  case 0x01: { /* IPv4 */
    uint8_t a[4];
    if (read_blk(fd, a, sizeof(a))) {
      return -1;
    }
    if (!inet_ntop(AF_INET, a, host, host_sz)) {
      goto fail;
    }
    break;
  }
  case 0x04: { /* IPv6 */
    uint8_t a[16];
    if (read_blk(fd, a, sizeof(a))) {
      return -1;
    }
    if (!inet_ntop(AF_INET6, a, host, host_sz)) {
      goto fail;
    }
    break;
  }
  case 0x03: { /* domain name */
    uint8_t len;
    char name[256];
    if (read_blk(fd, &len, 1) || len == 0) {
      return -1;
    }
    if (read_blk(fd, name, len)) {
      return -1;
    }
    if ((size_t)len >= host_sz || memchr(name, 0, len)) {
      goto fail;
    }
    memcpy(host, name, len);
    host[len] = 0;
    break;
  }
  default:
    socks5_reply(fd, 0x08); /* address type not supported */
    return -1;
  }

  uint16_t nport;
  if (read_blk(fd, &nport, sizeof(nport))) {
    return -1;
  }
  *port = ntohs(nport);
  return 0;

fail:
  socks5_reply(fd, 0x01); /* general failure */
  return -1;
}

static void *tunnel_worker(void *a) {
  tunnel_wargs *wa = (tunnel_wargs *)a;
  int sockfd = wa->sockfd;
  char closed = 0;

  char host[sizeof(((tunnel_conn_info *)0)->addr)];
  uint16_t port = 0;

  if (socks5_handshake(sockfd, host, sizeof(host), &port)) {
    PLOG("socks5 handshake failed");
    closed = 1;
    goto cleanup;
  }

  {
    char *buffer = calloc(1, wa->blksize);
    tunnel_hdr *hdr = set_hdr(buffer);
    hdr->id = wa->ent->id;
    hdr->flags = FLAG_NEW_CONN;
    hdr->len = HDR_CONN_SZ;
    tunnel_conn_info *ci = (tunnel_conn_info *)(buffer + HDR_SZ);
    ci->port = port;
    strncpy(ci->addr, host, sizeof(ci->addr) - 1);
    queue_push(queue_tx, buffer);
  }
  socks5_reply(sockfd, 0x00); /* succeeded */

  struct pollfd pollfds[2] = {
      {.fd = queue_get_eventfd(wa->ent->q), .events = POLLIN},
      {.fd = sockfd, .events = POLLIN}};
  while (1) {
    int r = poll(pollfds, 2, -1);
    if (r < 0) {
      if (errno == EINTR) {
        continue;
      }
      PERR("poll");
      goto cleanup;
    }

    if (pollfds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
      PLOG("queue error");
      goto cleanup;
    }
    if (pollfds[0].revents & POLLIN) {
      char *buffer = NULL;
      queue_pop(wa->ent->q, (void **)&buffer);

      tunnel_hdr *hdr = (tunnel_hdr *)buffer;

      if (hdr->flags & FLAG_CLOSE_CONN) {
        closed = 1;
        free(buffer);
        goto cleanup;
      }
      if (hdr->len > (uint32_t)(wa->blksize - HDR_SZ)) {
        PLOG("hdr->len too big");
        free(buffer);
        goto cleanup;
      }
      if (write_blk(sockfd, buffer + HDR_SZ, hdr->len)) {
        PERR("write_blk(sockfd)");
        free(buffer);
        goto cleanup;
      }
      free(buffer);
    }

    if (pollfds[1].revents & POLLIN) {
      char *buffer = calloc(1, wa->blksize);
      tunnel_hdr *hdr = set_hdr(buffer);

      ssize_t n = read(sockfd, buffer + HDR_SZ, wa->blksize - HDR_SZ);
      if (n < 0) {
        if (errno == EINTR) {
          free(buffer);
          continue;
        }
        PERR("read(sockfd)");
        free(buffer);
        goto cleanup;
      } else if (n == 0) {
        free(buffer);
        goto cleanup;
      } else {
        hdr->id = wa->ent->id;
        hdr->len = n;
        queue_push(queue_tx, buffer);
      }
    }
    if (pollfds[1].revents & (POLLERR | POLLNVAL)) {
      goto cleanup;
    }
  }
cleanup:
  if (!closed) {
    send_close_blk(wa->blksize, wa->ent->id);
  }

  pthread_mutex_lock(&tbl_mtx);
  HASH_DEL(tbl, wa->ent);
  pthread_mutex_unlock(&tbl_mtx);

  void *item;
  while (queue_size(wa->ent->q) > 0 && queue_pop(wa->ent->q, &item)) {
    free(item);
  }
  queue_free(wa->ent->q);

  free(wa->ent);
  free(wa);
  if (sockfd >= 0) {
    close(sockfd);
  }
  return NULL;
}

static void *tunnel_client(void *a) {
  struct iperf_test *test = (struct iperf_test *)a;
  int blksize = test->settings->blksize;

  int lfd = netannounce(AF_INET, SOCK_STREAM, LISTEN_ADDR, NULL, LISTEN_PORT);
  if (lfd < 0) {
    PERR("netannounce");
    return NULL;
  }

  int timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
  if (timerfd < 0) {
    PERR("timerfd_create");
    close(lfd);
    return NULL;
  }
  timerfd_arm(timerfd, rnd_idle_ms());

  struct pollfd pollfds[4] = {
      {.fd = efd_cli_exit, .events = POLLIN},
      {.fd = queue_get_eventfd(queue_rx), .events = POLLIN},
      {.fd = lfd, .events = POLLIN},
      {.fd = timerfd, .events = POLLIN}};
  while (1) {
    int r = poll(pollfds, 4, -1);
    if (r < 0) {
      if (errno != EINTR) {
        PERR("poll");
        break;
      }
      continue;
    }
    if (pollfds[0].revents & POLLIN) {
      uint64_t val;
      if (read(efd_cli_exit, &val, sizeof(val)) < 0) {
        PERR("read(efd_cli_exit)");
      }
      break;
    }
    if (pollfds[1].revents & POLLIN) {
      char *buffer = NULL;
      queue_pop(queue_rx, (void **)&buffer);

      tunnel_hdr *hdr = (tunnel_hdr *)buffer;

      if (hdr->flags & FLAG_EMPTY) {
        free(buffer);
        continue;
      }

      tunnel_wentry *we;
      pthread_mutex_lock(&tbl_mtx);
      HASH_FIND(hh, tbl, &hdr->id, sizeof(hdr->id), we);
      if (!we) {
        pthread_mutex_unlock(&tbl_mtx);
        free(buffer);
        continue;
      }
      queue_push(we->q, buffer);
      pthread_mutex_unlock(&tbl_mtx);
    }
    if (pollfds[2].revents & POLLIN) {
      int connfd = accept(lfd, NULL, NULL);
      if (connfd < 0) {
        if (errno != EINTR) {
          PERR("accept");
        }
      } else {
        tunnel_wentry *we = malloc(sizeof(tunnel_wentry));
        if (getrandom(&we->id, sizeof(we->id), 0) < 0) {
          PERR("getrandom");
          exit(EXIT_FAILURE);
        }
        we->q = queue_new();

        tunnel_wargs *wa = malloc(sizeof(tunnel_wargs));
        wa->ent = we;
        wa->sockfd = connfd;
        wa->blksize = blksize;

        pthread_mutex_lock(&tbl_mtx);
        HASH_ADD(hh, tbl, id, sizeof(we->id), we);
        pthread_mutex_unlock(&tbl_mtx);

        pthread_t th;
        if (pthread_create(&th, NULL, tunnel_worker, wa)) {
          PERR("pthread_create");

          pthread_mutex_lock(&tbl_mtx);
          HASH_DEL(tbl, we);
          pthread_mutex_unlock(&tbl_mtx);

          queue_free(we->q);
          free(we);
          free(wa);
          close(connfd);
        } else {
          pthread_detach(th);
        }
      }
    }
    if (pollfds[3].revents & POLLIN) {
      uint64_t val;
      read(timerfd, &val, sizeof(val));
      char *buffer = calloc(1, blksize);
      tunnel_hdr *hdr = set_hdr(buffer);
      hdr->flags = FLAG_EMPTY;
      queue_push(queue_tx, buffer);
      timerfd_arm(timerfd, rnd_idle_ms());
    }
  }

  close(lfd);
  close(timerfd);

  tunnel_wentry *ce, *tmp;
  pthread_mutex_lock(&tbl_mtx);
  HASH_ITER(hh, tbl, ce, tmp) {
    char *buffer = calloc(1, blksize);
    tunnel_hdr *hdr = set_hdr(buffer);
    hdr->flags = FLAG_CLOSE_CONN;
    queue_push(ce->q, buffer);
  }
  pthread_mutex_unlock(&tbl_mtx);
  return NULL;
}

static void tunnel_run_cb(struct iperf_test *test) {
  if (pthread_create(&cli_th, NULL, tunnel_client, test)) {
    PERR("pthread_create");
    exit(EXIT_FAILURE);
  }
}
void tunnel_client_init(struct iperf_test *test) {
  test->protocol->recv = tunnel_tcp_recv;
  test->protocol->send = tunnel_tcp_send;
  iperf_set_on_test_start_callback(test, tunnel_run_cb);
}
void tunnel_client_cleanup(void) {
  if (cli_th == 0) {
    return;
  }

  uint64_t val = 1;
  if (write(efd_cli_exit, &val, sizeof(val)) < 0) {
    PERR("write(efd_cli_exit)");
  }
  pthread_join(cli_th, NULL);
  cli_th = 0;

  void *item;
  while (queue_size(queue_rx) > 0 && queue_pop(queue_rx, &item)) {
    free(item);
  }
  while (queue_size(queue_tx) > 0 && queue_pop(queue_tx, &item)) {
    free(item);
  }
}
