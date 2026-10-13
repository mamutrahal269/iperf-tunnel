#include "iperf_config.h"

#include "queue.h"
#include <asm-generic/errno-base.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <unistd.h>

struct queue *queue_new(void) {
  struct queue *q = malloc(sizeof(struct queue));
  if (!q)
    return NULL;

  q->front = NULL;
  q->rear = NULL;
  q->size = 0;

  if (pthread_mutex_init(&q->mutex, NULL) != 0) {
    free(q);
    return NULL;
  }

  q->efd = eventfd(0, EFD_SEMAPHORE);
  if (q->efd == -1) {
    pthread_mutex_destroy(&q->mutex);
    free(q);
    return NULL;
  }

  return q;
}

void queue_free(struct queue *q) {
  if (!q)
    return;

  pthread_mutex_lock(&q->mutex);
  struct queue_node *curr = q->front;
  while (curr) {
    struct queue_node *next = curr->next;
    free(curr);
    curr = next;
  }
  pthread_mutex_unlock(&q->mutex);

  pthread_mutex_destroy(&q->mutex);
  if (q->efd != -1) {
    close(q->efd);
  }
  free(q);
}

int queue_get_eventfd(const struct queue *q) { return q->efd; }

bool queue_is_empty(struct queue *q) {
  pthread_mutex_lock(&q->mutex);
  bool empty = (q->front == NULL);
  pthread_mutex_unlock(&q->mutex);
  return empty;
}

size_t queue_size(struct queue *q) {
  pthread_mutex_lock(&q->mutex);
  size_t sz = q->size;
  pthread_mutex_unlock(&q->mutex);
  return sz;
}

bool queue_push(struct queue *q, void *item) {
  struct queue_node *node = malloc(sizeof(struct queue_node));
  if (!node)
    return false;

  node->data = item;
  node->next = NULL;

  pthread_mutex_lock(&q->mutex);

  if (q->rear == NULL) {
    q->front = node;
    q->rear = node;
  } else {
    q->rear->next = node;
    q->rear = node;
  }
  q->size++;

  pthread_mutex_unlock(&q->mutex);

  uint64_t val = 1;
  while (1) {
    int n = write(q->efd, &val, sizeof(val));
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    return true;
  }
}

bool queue_pop(struct queue *q, void **out_item) {
  uint64_t val;
  while (1) {
    int n = read(q->efd, &val, sizeof(val));
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    break;
  }
  pthread_mutex_lock(&q->mutex);

  if (q->front == NULL) {
    pthread_mutex_unlock(&q->mutex);
    return false;
  }

  struct queue_node *node = q->front;
  if (out_item) {
    *out_item = node->data;
  }

  q->front = q->front->next;
  if (q->front == NULL) {
    q->rear = NULL;
  }
  q->size--;

  pthread_mutex_unlock(&q->mutex);

  free(node);

  return true;
}
