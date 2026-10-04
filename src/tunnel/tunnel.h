#pragma once

#include "iperf_api.h"
#include "queue.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HDR_SZ sizeof(tunnel_hdr)
#define HDR_CONN_SZ sizeof(tunnel_conn_info)
#define PERR(msg)                                                              \
  fprintf(stderr, "%s: %s: %s\n", __func__, msg, strerror(errno))
#define PLOG(msg) fprintf(stderr, "%s: %s\n", __func__, msg)

extern struct queue *queue_tx;
extern struct queue *queue_rx;

enum flag {
  FLAG_EMPTY = (1 << 0),
  FLAG_NEW_CONN = (1 << 1),
  FLAG_CLOSE_CONN = (1 << 2)
};
typedef struct __attribute__((packed)) {
  uint16_t port;
  char addr[256];
} tunnel_conn_info;
typedef struct __attribute__((packed)) {
  uint64_t id;
  uint32_t len;
  enum flag flags;
} tunnel_hdr;

int tunnel_tcp_recv(struct iperf_stream *sp);
int tunnel_tcp_send(struct iperf_stream *sp);
int write_blk(int fd, const void *buf, size_t blksize);
int read_blk(int fd, void *buf, size_t blksize);

static inline tunnel_hdr *set_hdr(void *buffer) {
  tunnel_hdr *hdr = (tunnel_hdr *)buffer;
  memset(hdr, 0, sizeof(tunnel_hdr));
  return hdr;
}
static inline void send_close_blk(int blksize, uint64_t id) {
  char *buffer = malloc(blksize);
  tunnel_hdr *hdr = set_hdr(buffer);
  hdr->id = id;
  hdr->flags = FLAG_CLOSE_CONN;
  queue_push(queue_tx, buffer);
}
