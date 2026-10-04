#include "tunnel.h"
#include "iperf.h"
#include "iperf_api.h"
#include "queue.h"

#include <unistd.h>

struct queue *queue_tx;
struct queue *queue_rx;
static __attribute__((constructor)) void q_init() {
  queue_tx = queue_new();
  queue_rx = queue_new();

  if (!queue_rx || !queue_tx) {
    fprintf(stderr, "failed to initialize queue(s)\n");
    exit(EXIT_FAILURE);
  }
}

int write_blk(int fd, const void *buf, size_t blksize) {
  size_t written = 0;
  while (written < blksize) {
    ssize_t n = write(fd, buf + written, blksize - written);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    written += n;
  }
  return 0;
}

int read_blk(int fd, void *buf, size_t blksize) {
  size_t readed = 0;
  while (readed < blksize) {
    ssize_t n = read(fd, buf + readed, blksize - readed);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    if (n == 0) {
      return -1;
    }
    readed += n;
  }
  return 0;
}

int tunnel_tcp_recv(struct iperf_stream *sp) {
  int blk = sp->settings->blksize;

  char *buffer = malloc(blk);
  if (read_blk(sp->socket, buffer, blk)) {
    return -1;
  }
  queue_push(queue_rx, buffer);
  if (sp->test->state == TEST_RUNNING) {
    sp->result->bytes_received += blk;
    sp->result->bytes_received_this_interval += blk;
  }
  return blk;
}

int tunnel_tcp_send(struct iperf_stream *sp) {
  int blk = sp->settings->blksize;

  char *buffer = NULL;
  queue_pop(queue_tx, (void **)&buffer);
  if (write_blk(sp->socket, buffer, blk)) {
    free(buffer);
    return -1;
  }
  free(buffer);
  sp->result->bytes_sent += blk;
  sp->result->bytes_sent_this_interval += blk;
  return 0;
}
