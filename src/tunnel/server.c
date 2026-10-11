#include "server.h"
#include "iperf.h"
#include "iperf_api.h"
#include "net.h"
#include "queue.h"
#include "tunnel.h"

#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <uthash.h>

typedef struct {
  uint64_t id;
  struct queue *q;
  UT_hash_handle hh;
} tunnel_wentry;
typedef struct {
  tunnel_wentry *ent;
  tunnel_conn_info conn;
  int blksize;
} tunnel_wargs;

static tunnel_wentry *tbl;
static pthread_mutex_t tbl_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_t serv_th;
static int efd_serv_exit = -1;
static __attribute__((constructor)) void efd_init() {
  if ((efd_serv_exit = eventfd(0, EFD_SEMAPHORE)) < 0) {
    PERR("eventfd");
    exit(EXIT_FAILURE);
  }
}

static void *tunnel_worker(void *a) {
  tunnel_wargs *wa = (tunnel_wargs *)a;
  char closed = 0;

  wa->conn.addr[sizeof(wa->conn.addr) - 1] = '\0';

  int sockfd = netdial(AF_UNSPEC, SOCK_STREAM, NULL, NULL, 0, wa->conn.addr,
                       wa->conn.port, -1);
  if (sockfd < 0) {
    PERR("connection failed");
    goto cleanup;
  }

  fprintf(stderr, "connected to %s:%d (id %ld)\n", wa->conn.addr, wa->conn.port,
          wa->ent->id);

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
      if (hdr->len > (wa->blksize - HDR_SZ)) {
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

      int n = read(sockfd, buffer + HDR_SZ, wa->blksize - HDR_SZ);
      if (n < 0) {
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
    if (pollfds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
      goto cleanup;
    }
  }
cleanup:
  if (wa) {
    if (wa->ent) {

      if (!closed) {
        send_close_blk(wa->blksize, wa->ent->id);
      }

      pthread_mutex_lock(&tbl_mtx);
      HASH_DEL(tbl, wa->ent);
      pthread_mutex_unlock(&tbl_mtx);

      fprintf(stderr, "connection to %s:%d closed(id %ld)\n", wa->conn.addr,
              wa->conn.port, wa->ent->id);

      if (wa->ent->q) {
        void *item;
        while (queue_size(wa->ent->q) > 0 && queue_pop(wa->ent->q, &item)) {
          free(item);
        }
        queue_free(wa->ent->q);
      }

      free(wa->ent);
    }
    free(wa);
  }
  if (sockfd >= 0) {
    close(sockfd);
  }
  return NULL;
}

static void *tunnel_server(void *a) {
  struct iperf_test *test = (struct iperf_test *)a;
  int blksize = test->settings->blksize;

  struct pollfd pollfds[2] = {
      {.fd = efd_serv_exit, .events = POLLIN},
      {.fd = queue_get_eventfd(queue_rx), .events = POLLIN}};
  while (1) {
    int r = poll(pollfds, 2, 500); // TODO:  рандомное время ожидания
    if (r < 0) {
      if (errno != EINTR) {
        PERR("poll");
        exit(EXIT_FAILURE);
      }
      continue;
    } else if (r == 0) {
      char *buffer = calloc(1, blksize);
      tunnel_hdr *hdr = set_hdr(buffer);
      hdr->flags = FLAG_EMPTY;
      queue_push(queue_tx, buffer);
      continue;
    }
    if (pollfds[0].revents & POLLIN) {
      uint64_t val;
      read(efd_serv_exit, &val, sizeof(val));
      tunnel_wentry *we, *tmp;
      pthread_mutex_lock(&tbl_mtx);
      HASH_ITER(hh, tbl, we, tmp) {
        char *buffer = malloc(blksize);
        tunnel_hdr *hdr = set_hdr(buffer);
        hdr->flags = FLAG_CLOSE_CONN;
        queue_push(we->q, buffer);
      }
      pthread_mutex_unlock(&tbl_mtx);
      return NULL;
    }
    if (pollfds[1].revents & POLLIN) {
      char *buffer = NULL;
      queue_pop(queue_rx, (void *)&buffer);
      tunnel_hdr *hdr = (tunnel_hdr *)buffer;

      if (hdr->flags & FLAG_EMPTY) {
        free(buffer);
        continue;
      }

      tunnel_wentry *we;

      pthread_mutex_lock(&tbl_mtx);
      HASH_FIND(hh, tbl, &hdr->id, sizeof(hdr->id), we);
      if (hdr->flags & FLAG_NEW_CONN) {
        pthread_mutex_unlock(&tbl_mtx);

        if (we) {
          PLOG("FLAG_NEW_CONN for existing connectivity");
          free(buffer);
          continue;
        }
        we = malloc(sizeof(tunnel_wentry));
        we->id = hdr->id;
        we->q = queue_new();

        tunnel_wargs *wa = malloc(sizeof(tunnel_wargs));
        wa->ent = we;
        wa->blksize = blksize;
        memcpy(&wa->conn, buffer + HDR_SZ, sizeof(tunnel_conn_info));

        pthread_mutex_lock(&tbl_mtx);
        HASH_ADD(hh, tbl, id, sizeof(we->id), we);
        pthread_mutex_unlock(&tbl_mtx);

        pthread_t th;
        if (pthread_create(&th, NULL, tunnel_worker, wa)) {
          PERR("pthread_create");
          send_close_blk(blksize, hdr->id);

          pthread_mutex_lock(&tbl_mtx);
          HASH_DEL(tbl, we);
          pthread_mutex_unlock(&tbl_mtx);

          queue_free(we->q);
          free(we);
          free(wa);
          free(buffer);

          continue;
        }
        pthread_detach(th);
        free(buffer);
      } else {
        if (!we) {
          pthread_mutex_unlock(&tbl_mtx);
          free(buffer);
          continue;
        }
        queue_push(we->q, buffer);
        pthread_mutex_unlock(&tbl_mtx);
      }
    }
  }
}
static void tunnel_run_cb(struct iperf_test *test) {
  if (pthread_create(&serv_th, NULL, tunnel_server, test)) {
    PERR("pthread_create");
    exit(EXIT_FAILURE);
  }
  printf("server started\n");
}
void tunnel_server_init(struct iperf_test *test) {
  test->protocol->recv = tunnel_tcp_recv;
  test->protocol->send = tunnel_tcp_send;
  iperf_set_on_test_start_callback(test, tunnel_run_cb);
}
void tunnel_server_cleanup() {
  uint64_t val = 1;
  write(efd_serv_exit, &val, sizeof(val));
  pthread_join(serv_th, NULL);

  void *item;
  while (queue_size(queue_rx) > 0 && queue_pop(queue_rx, &item)) {
    free(item);
  }
  while (queue_size(queue_tx) > 0 && queue_pop(queue_tx, &item)) {
    free(item);
  }
  printf("server cancelled\n");
}
